"""Saving and loading the fitted model.

The manifest travels with the pipeline: column order, training means, the
operating threshold and how it was chosen. The interface reads its numbers
from here rather than hardcoding them, so a retrained model updates the header
and the threshold marker without anyone editing a template.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from functools import lru_cache

import joblib
import numpy as np

from ..config import MODELS

MODEL_PATH = MODELS / "baseline.joblib"
BASE_MODEL_PATH = MODELS / "baseline_uncalibrated.joblib"
MANIFEST_PATH = MODELS / "manifest.json"


@dataclass
class Manifest:
    version: str
    kind: str
    columns: list[str]
    means: list[float]
    coefficients: dict[str, float]
    threshold: float
    threshold_basis: str
    calibration: str
    base_rate: float
    pr_auc: float
    recall_at_threshold: float
    split: str
    caveat: str
    feature_scope: str
    trained_at: str
    held_back: list[str] = field(default_factory=list)
    brier: float = 0.0
    ece: float = 0.0

    def save(self) -> None:
        MANIFEST_PATH.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls) -> "Manifest | None":
        if not MANIFEST_PATH.exists():
            return None
        try:
            return cls(**json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, TypeError):
            return None

    def header(self) -> str:
        return f"{self.version} / {self.calibration} / threshold {self.threshold:.2f}"

    def probability_label(self) -> str:
        """What the interface should call the number it displays."""
        return ("Calibrated probability" if self.calibration != "uncalibrated"
                else "Uncalibrated score")


def save_pipeline(pipe, base_pipe=None) -> None:
    joblib.dump(pipe, MODEL_PATH)
    if base_pipe is not None:
        joblib.dump(base_pipe, BASE_MODEL_PATH)


def _mtime(path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


# One load at a time. The web app warms these on a background thread when a
# check starts, and a result that arrives mid-warm-up would otherwise miss the
# cache and deserialise the same pickle a second time alongside it; with the
# lock it waits for the copy already on its way.
_LOAD_LOCK = threading.Lock()


@lru_cache(maxsize=4)
def _load_cached(path_str: str, _mtime_key: float):
    return joblib.load(path_str)


def _load(path) -> object:
    with _LOAD_LOCK:
        return _load_cached(str(path), _mtime(path))


def load_pipeline():
    """The calibrated model — this produces the probability shown to users.

    Cached on (path, mtime), so a scan reuses the loaded object and a retrained
    model is still picked up without a restart. Every scan used to deserialise
    these files afresh -- tens of megabytes of pickle per request on a service
    with a 2 GB limit -- and, because each load produced a new object, the SHAP
    explainer keyed on `id(model)` never hit its cache either.
    """
    if not MODEL_PATH.exists():
        return None
    return _load(MODEL_PATH)


def load_base_pipeline():
    """The uncalibrated pipeline, used only for per-feature attributions.

    A calibrator wraps its estimator and hides `named_steps`, so the explainer
    cannot reach the coefficients through it.
    """
    if BASE_MODEL_PATH.exists():
        return _load(BASE_MODEL_PATH)
    return load_pipeline()


def is_trained() -> bool:
    return MODEL_PATH.exists() and MANIFEST_PATH.exists()


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------

def linear_contributions(pipe, x: np.ndarray, means: np.ndarray,
                         columns: list[str]) -> dict[str, float]:
    """Exact per-feature contributions in log-odds.

    For a linear model these are not an approximation of SHAP — they *are* the
    SHAP values: coefficient x (value - expected value), measured on the scale
    the model actually works on. Running the `shap` library over a logistic
    regression would compute the same numbers more slowly. Tree models go
    through `_tree_contributions` instead.
    """
    imputer = pipe.named_steps["impute"]
    scaler = pipe.named_steps["scale"]
    coefs = pipe.named_steps["clf"].coef_[0]

    raw = x.reshape(1, -1)
    if "clip" in pipe.named_steps:
        # Attribute the value the model actually saw, not the raw one.
        raw = pipe.named_steps["clip"].transform(raw)
    filled = imputer.transform(raw)
    scaled = scaler.transform(filled)[0]
    baseline = scaler.transform(means.reshape(1, -1))[0]

    return {c: float(coefs[i] * (scaled[i] - baseline[i])) for i, c in enumerate(columns)}


def _tree_contributions(pipe, x: np.ndarray, columns: list[str]) -> dict[str, float]:
    """Per-feature contributions for a gradient-boosted model, via TreeSHAP.

    Gradient boosting has no coefficients, so `linear_contributions` returns
    nothing for it -- which silently emptied the reasons panel the first time a
    tree model was persisted. TreeSHAP gives exact contributions to the raw
    margin, so these stay on the same log-odds scale the linear attributions
    used and the interface needs no special case.

    `treeshap` is the algorithm without the `shap` package, whose numba,
    llvmlite and pandas dependencies were 285 MB of a 500 MB function. The two
    agree to 1e-15 on rows from the evidence table; `tests/test_treeshap.py`
    keeps it that way.
    """
    from . import treeshap

    model = pipe.named_steps["clf"] if hasattr(pipe, "named_steps") else pipe
    values = treeshap.contributions(model, x)
    return {c: float(values[i]) for i, c in enumerate(columns) if i < len(values)}


def is_linear(pipe) -> bool:
    return hasattr(pipe, "named_steps") and hasattr(
        pipe.named_steps.get("clf"), "coef_")


def contributions(pipe, x: np.ndarray, means: np.ndarray,
                  columns: list[str]) -> dict[str, float]:
    """Per-feature attribution, whichever model is in use.

    Both branches report log-odds, so a reason means the same thing to a reader
    regardless of which model produced the score.
    """
    if is_linear(pipe):
        return linear_contributions(pipe, x, means, columns)
    return _tree_contributions(pipe, x, columns)
