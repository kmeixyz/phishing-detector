"""Feature plumbing.

Two ideas carry the whole layer:

1. Extractors are pure functions over an evidence bundle. No network calls
   happen below this line, which is what lets them be unit-tested against
   fixtures instead of against the live internet.

2. A missing feature is not a zero. When RDAP times out, `domain_age_days`
   is *absent*, and that is different from a domain aged zero days. Absence is
   carried explicitly through to the model (which handles NaN natively) and to
   the interface, which reports "49 of 63 features present" rather than
   quietly scoring on imputed values.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable

import numpy as np


@dataclass(frozen=True)
class Feature:
    """One named signal, which may or may not have been observable."""

    name: str
    value: float | None
    present: bool = True
    detail: str = ""  # human-readable rendering, e.g. "0 to paypal.com"

    @classmethod
    def missing(cls, name: str, why: str = "") -> "Feature":
        return cls(name=name, value=None, present=False, detail=why)

    def as_float(self) -> float:
        return float("nan") if not self.present or self.value is None else float(self.value)


@dataclass
class FeatureSet:
    """An ordered, self-describing collection of features."""

    features: dict[str, Feature] = field(default_factory=dict)

    def add(self, name: str, value: Any, detail: str = "") -> None:
        if value is None:
            self.features[name] = Feature.missing(name, detail)
            return
        if isinstance(value, bool):
            value = 1.0 if value else 0.0
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            self.features[name] = Feature.missing(name, detail or f"non-numeric: {value!r}")
            return
        if math.isnan(numeric):
            self.features[name] = Feature.missing(name, detail)
            return
        self.features[name] = Feature(name=name, value=numeric, detail=detail)

    def add_missing(self, name: str, why: str = "") -> None:
        self.features[name] = Feature.missing(name, why)

    def update(self, other: "FeatureSet") -> None:
        self.features.update(other.features)

    def names(self) -> list[str]:
        return list(self.features)

    def vector(self, order: Iterable[str]) -> np.ndarray:
        """Dense vector in a fixed column order, NaN where absent.

        The order comes from the trained model's manifest, never from dict
        insertion order, so a new extractor cannot silently shift columns
        underneath a model that was fitted before it existed.
        """
        return np.array(
            [self.features[n].as_float() if n in self.features else float("nan") for n in order],
            dtype=float,
        )

    def presence(self, order: Iterable[str] | None = None) -> tuple[int, int]:
        """(present, total) against the model's column order if given."""
        cols = list(order) if order is not None else self.names()
        present = sum(1 for n in cols if n in self.features and self.features[n].present)
        return present, len(cols)

    def missing_names(self, order: Iterable[str] | None = None) -> list[str]:
        cols = list(order) if order is not None else self.names()
        return [n for n in cols if n not in self.features or not self.features[n].present]

    def to_dict(self) -> dict[str, float | None]:
        return {n: (f.value if f.present else None) for n, f in self.features.items()}

    def __len__(self) -> int:
        return len(self.features)

    def __contains__(self, name: object) -> bool:
        return name in self.features

    def __getitem__(self, name: str) -> Feature:
        return self.features[name]


def sanitise_html(html: str) -> str:
    """Drop lone surrogates so downstream UTF-8 encoding cannot raise.

    BeautifulSoup encodes to UTF-8 internally, and an unpaired surrogate makes
    that raise — which killed the whole scan for a page rather than degrading
    the content features. Attacker-controlled markup is exactly where malformed
    encodings turn up, so this cannot be allowed to propagate.
    """
    if not html:
        return html
    try:
        html.encode("utf-8")
        return html
    except UnicodeEncodeError:
        return html.encode("utf-8", "replace").decode("utf-8", "replace")


def shannon_entropy(text: str) -> float:
    """Bits per character. High values flag DGA-style random-looking names."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
