"""Exact TreeSHAP for scikit-learn's HistGradientBoosting, without `shap`.

The reasons panel needs one thing from SHAP: per-feature contributions to the
raw log-odds margin of a gradient-boosted model, for one feature vector at a
time. The `shap` package delivers that, and brings numba, llvmlite and pandas
with it -- about 285 MB of a Vercel function whose limit is 500. This is the
same algorithm on its own: Lundberg et al., "Consistent Individualized Feature
Attribution for Tree Ensembles", Algorithm 2 (path-dependent TreeSHAP), with
node sample counts as cover, which is what `shap.TreeExplainer(model)` uses
for this model type when given no background data.

It is exact, not an approximation: the contributions sum to the raw margin
minus the expected value, and `tests/test_treeshap.py` checks them against
`shap` itself on rows from the evidence table.

Only numeric splits are handled. The fitted model has no categorical
features; one that did would be refused rather than explained wrongly.
"""

from __future__ import annotations

import numpy as np


class _PathElement:
    __slots__ = ("d", "z", "o", "w")

    def __init__(self, d: int, z: float, o: float, w: float):
        self.d, self.z, self.o, self.w = d, z, o, w


def _extend(m: list[_PathElement], p_z: float, p_o: float, p_i: int) -> None:
    depth = len(m)
    m.append(_PathElement(p_i, p_z, p_o, 1.0 if depth == 0 else 0.0))
    for i in range(depth - 1, -1, -1):
        m[i + 1].w += p_o * m[i].w * (i + 1) / (depth + 1)
        m[i].w = p_z * m[i].w * (depth - i) / (depth + 1)


def _unwound_sum(m: list[_PathElement], i: int) -> float:
    """Sum of path weights with element `i` removed, without building the path."""
    depth = len(m) - 1
    o, z = m[i].o, m[i].z
    n = m[depth].w
    total = 0.0
    for j in range(depth - 1, -1, -1):
        if o != 0:
            t = n * (depth + 1) / ((j + 1) * o)
            total += t
            n = m[j].w - t * z * (depth - j) / (depth + 1)
        else:
            total += (m[j].w * (depth + 1)) / (z * (depth - j))
    return total


def _unwind(m: list[_PathElement], i: int) -> list[_PathElement]:
    depth = len(m) - 1
    out = [_PathElement(e.d, e.z, e.o, e.w) for e in m]
    o, z = out[i].o, out[i].z
    n = out[depth].w
    for j in range(depth - 1, -1, -1):
        if o != 0:
            t = out[j].w
            out[j].w = n * (depth + 1) / ((j + 1) * o)
            n = t - out[j].w * z * (depth - j) / (depth + 1)
        else:
            out[j].w = (out[j].w * (depth + 1)) / (z * (depth - j))
    for j in range(i, depth):
        out[j].d, out[j].z, out[j].o = out[j + 1].d, out[j + 1].z, out[j + 1].o
    out.pop()
    return out


def _tree_shap(nodes, x: np.ndarray, phi: np.ndarray) -> None:
    value, count = nodes["value"], nodes["count"]
    feature, threshold = nodes["feature_idx"], nodes["num_threshold"]
    left, right, leaf = nodes["left"], nodes["right"], nodes["is_leaf"]
    missing_left = nodes["missing_go_to_left"]

    def recurse(j: int, m: list[_PathElement], p_z: float, p_o: float, p_i: int) -> None:
        m = [_PathElement(e.d, e.z, e.o, e.w) for e in m]
        _extend(m, p_z, p_o, p_i)
        if leaf[j]:
            v = float(value[j])
            for i in range(1, len(m)):
                phi[m[i].d] += _unwound_sum(m, i) * (m[i].o - m[i].z) * v
            return
        f = int(feature[j])
        xv = x[f]
        # The predictor's own rule: NaN follows the learned default side,
        # anything else goes left at or below the threshold.
        goes_left = bool(missing_left[j]) if np.isnan(xv) else xv <= threshold[j]
        hot, cold = (left[j], right[j]) if goes_left else (right[j], left[j])
        i_z = i_o = 1.0
        k = next((k for k in range(1, len(m)) if m[k].d == f), None)
        if k is not None:
            i_z, i_o = m[k].z, m[k].o
            m = _unwind(m, k)
        cover = float(count[j])
        recurse(int(hot), m, i_z * count[hot] / cover, i_o, f)
        recurse(int(cold), m, i_z * count[cold] / cover, 0.0, f)

    recurse(0, [], 1.0, 1.0, -1)


def contributions(model, x: np.ndarray) -> np.ndarray:
    """Per-feature SHAP values on the raw margin for one row `x`.

    `model` is a fitted binary HistGradientBoostingClassifier. The result has
    one entry per column of `x`; adding the expected value gives the margin.
    """
    predictors = model._predictors
    if any(len(per_iter) != 1 for per_iter in predictors):
        raise ValueError("only binary HistGradientBoosting models are supported")
    if any(p[0].nodes["is_categorical"].any() for p in predictors):
        raise ValueError("categorical splits are not supported")
    x = np.asarray(x, dtype=float).reshape(-1)
    phi = np.zeros(x.shape[0] + 1)  # the extra slot absorbs the root's dummy feature
    for (predictor,) in predictors:
        _tree_shap(predictor.nodes, x, phi)
    return phi[:-1]


def expected_value(model) -> float:
    """The margin's mean over the training distribution, by node cover."""
    total = float(np.asarray(model._baseline_prediction).reshape(-1)[0])
    for (predictor,) in model._predictors:
        nodes = predictor.nodes
        leaves = nodes["is_leaf"].astype(bool)
        total += float((nodes["value"][leaves] * nodes["count"][leaves]).sum()
                       / nodes["count"][0])
    return total
