"""Bootstrap-ensemble prediction intervals.

WHAT THIS MEASURES, AND WHAT IT DOES NOT

An ensemble of models is fitted on bootstrap resamples of the training set,
and the spread of their predictions on a given URL becomes the interval. That
is *estimation* uncertainty: how much the verdict depends on which 560
phishing URLs happened to be collected. On a corpus this small it is wide, and
being wide is the honest outcome.

It is NOT a measure of missing evidence. A scan where RDAP timed out and the
page never rendered can still produce a narrow interval, because every model
in the ensemble is equally blind to the same absent features. Evidence
thinness is reported separately, by the coverage panel and the cross-check's
blocking concerns, and conflating the two would let a confident-looking band
paper over a half-failed scan.

The design's "borderline" state falls straight out of this: an interval that
straddles the operating threshold means the point estimate is not stable
enough to act on, which is a case for a human rather than for rounding.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from functools import lru_cache

import joblib
import numpy as np

from ..config import MODELS

ENSEMBLE_PATH = MODELS / "bootstrap_ensemble.joblib"
DEFAULT_MEMBERS = 25
LOW_Q, HIGH_Q = 5.0, 95.0  # a 90% interval


@dataclass
class Interval:
    low: float
    high: float
    point: float
    members: int

    @property
    def width(self) -> float:
        return self.high - self.low

    def straddles(self, threshold: float) -> bool:
        """True when the threshold falls inside the interval."""
        return self.low <= threshold <= self.high


def fit_ensemble(build_estimator, X, y, members: int = DEFAULT_MEMBERS,
                 seed: int = 0, model_kind: str = "lr", calibrate: str = "sigmoid"):
    """Fit `members` models on bootstrap resamples of (X, y).

    Each resample is drawn with replacement at the original size. Resamples
    that happen to contain a single class are skipped rather than fitted —
    with a skewed base rate that occurs, and a one-class member would
    contribute a constant prediction to every interval.
    """
    rng = np.random.default_rng(seed)
    n = len(y)
    models = []
    for _ in range(members):
        idx = rng.integers(0, n, size=n)
        y_b = y[idx]
        if len(np.unique(y_b)) < 2:
            continue
        est = build_estimator(model_kind, calibrate)
        try:
            est.fit(X[idx], y_b)
        except ValueError:
            continue  # e.g. a calibration fold ends up single-class
        models.append(est)
    return models


def save(models) -> None:
    joblib.dump(models, ENSEMBLE_PATH)


def load():
    """The bootstrap ensemble, cached on (path, mtime).

    It is tens of megabytes of pickle and it was being deserialised on every
    single scan, against a 2 GB memory limit -- `persist.load_pipeline` was
    fixed for exactly this reason and this caller was missed, while the note
    over there claimed the problem was solved. Same key, so a retrained
    ensemble is still picked up without a restart.
    """
    if not ENSEMBLE_PATH.exists():
        return None
    with _LOAD_LOCK:
        return _load_cached(str(ENSEMBLE_PATH), ENSEMBLE_PATH.stat().st_mtime)


# Same reason as persist._LOAD_LOCK: a result during the warm-up waits for
# that load rather than starting a second one.
_LOAD_LOCK = threading.Lock()


@lru_cache(maxsize=2)
def _load_cached(path_str: str, _mtime_key: float):
    return joblib.load(path_str)


def predict(models, x: np.ndarray, point: float) -> Interval | None:
    """Percentile interval across ensemble members for one feature vector."""
    if not models:
        return None
    preds = []
    for m in models:
        try:
            preds.append(float(m.predict_proba(x.reshape(1, -1))[0, 1]))
        except Exception:  # noqa: BLE001 - a broken member must not break the scan
            continue
    if len(preds) < 3:
        return None
    arr = np.array(preds)
    low, high = float(np.percentile(arr, LOW_Q)), float(np.percentile(arr, HIGH_Q))

    # The band must contain the number it is drawn around. The point comes from
    # the persisted calibrated model and the band from 25 separately-fitted
    # bootstrap models, so nothing forces them to agree — and they did not:
    # census-bot.tech rendered as "0.97, 90% interval 0.98 to 0.99", a point
    # sitting below its own lower bound, which is incoherent to a reader.
    # Widening to include the point is the honest reconciliation: if the
    # production model lands outside the ensemble's spread, the real
    # uncertainty is at least that wide.
    return Interval(
        low=min(low, point),
        high=max(high, point),
        point=point,
        members=len(preds),
    )
