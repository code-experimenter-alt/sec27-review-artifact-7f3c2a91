"""Small deterministic router models with chronological fit/calibration hooks."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Protocol

import numpy as np


class ScoreModel(Protocol):
    def fit(
        self,
        features: np.ndarray,
        labels: np.ndarray,
        sample_weight: np.ndarray | None = None,
    ) -> "ScoreModel": ...

    def score(self, features: np.ndarray) -> np.ndarray: ...

    @property
    def memory_bytes(self) -> int: ...


def _validated_xy(
    features: np.ndarray,
    labels: np.ndarray,
    sample_weight: np.ndarray | None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x = np.asarray(features, dtype=np.float64)
    y = np.asarray(labels, dtype=np.float64)
    if x.ndim != 2 or x.shape[0] == 0:
        raise ValueError("features must be a nonempty two-dimensional array")
    if y.shape != (x.shape[0],) or np.any((y < 0) | (y > 1)):
        raise ValueError("labels must have one [0, 1] value per row")
    if not np.all(np.isfinite(x)) or not np.all(np.isfinite(y)):
        raise ValueError("features and labels must be finite")
    if sample_weight is None:
        weight = np.ones(x.shape[0], dtype=np.float64)
    else:
        weight = np.asarray(sample_weight, dtype=np.float64)
        if weight.shape != (x.shape[0],):
            raise ValueError("sample_weight must have one value per row")
        if np.any(weight < 0) or not np.all(np.isfinite(weight)):
            raise ValueError("sample weights must be finite and nonnegative")
    if float(weight.sum()) <= 0:
        raise ValueError("sample weights must have positive total mass")
    return x, y, weight


def _sigmoid(value: np.ndarray) -> np.ndarray:
    clipped = np.clip(value, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


class LogisticScore:
    """L2-regularized logistic model fitted by deterministic Newton steps."""

    def __init__(self, l2: float = 1e-3, max_iterations: int = 100) -> None:
        if type(l2) not in {int, float} or not math.isfinite(l2) or l2 < 0:
            raise ValueError("l2 must be finite and nonnegative")
        if type(max_iterations) is not int or max_iterations <= 0:
            raise ValueError("max_iterations must be positive")
        self.l2 = l2
        self.max_iterations = max_iterations
        self.mean_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None
        self.coefficients_: np.ndarray | None = None

    def fit(
        self,
        features: np.ndarray,
        labels: np.ndarray,
        sample_weight: np.ndarray | None = None,
    ) -> "LogisticScore":
        x, y, weight = _validated_xy(features, labels, sample_weight)
        self.mean_ = np.average(x, axis=0, weights=weight)
        centered = x - self.mean_
        variance = np.average(centered * centered, axis=0, weights=weight)
        self.scale_ = np.sqrt(variance)
        self.scale_[self.scale_ < 1e-12] = 1.0
        design = np.column_stack((np.ones(x.shape[0]), centered / self.scale_))
        coefficients = np.zeros(design.shape[1], dtype=np.float64)
        penalty = np.eye(design.shape[1], dtype=np.float64) * self.l2
        penalty[0, 0] = 0.0
        total_weight = float(weight.sum())
        for _ in range(self.max_iterations):
            probability = _sigmoid(design @ coefficients)
            gradient = design.T @ (weight * (probability - y)) / total_weight
            gradient += penalty @ coefficients
            curvature = weight * probability * (1.0 - probability)
            hessian = (design.T * curvature) @ design / total_weight + penalty
            hessian += np.eye(hessian.shape[0]) * 1e-10
            try:
                step = np.linalg.solve(hessian, gradient)
            except np.linalg.LinAlgError:
                step = np.linalg.lstsq(hessian, gradient, rcond=None)[0]
            coefficients -= step
            if not np.all(np.isfinite(coefficients)):
                raise ValueError("logistic optimization left the finite numeric domain")
            if float(np.max(np.abs(step))) < 1e-9:
                break
        self.coefficients_ = coefficients
        return self

    def score(self, features: np.ndarray) -> np.ndarray:
        if self.mean_ is None or self.scale_ is None or self.coefficients_ is None:
            raise RuntimeError("model must be fitted before scoring")
        x = np.asarray(features, dtype=np.float64)
        if x.ndim != 2 or x.shape[1] != self.mean_.shape[0]:
            raise ValueError("feature width does not match the fitted model")
        if not np.all(np.isfinite(x)):
            raise ValueError("features must be finite")
        design = np.column_stack((np.ones(x.shape[0]), (x - self.mean_) / self.scale_))
        return _sigmoid(design @ self.coefficients_)

    @property
    def memory_bytes(self) -> int:
        arrays = (self.mean_, self.scale_, self.coefficients_)
        return sum(array.nbytes for array in arrays if array is not None) + 32


class DecisionStumpScore:
    """One-split probability tree selected by weighted Brier loss.

    A public, deterministic stable-feature hash breaks probability ties.  The
    perturbation is too small to change ordinary leaf ordering, but prevents a
    two-leaf model from silently collapsing an explicitly configured region
    count during quantile calibration.
    """

    def __init__(self, maximum_candidates: int = 64, seed: int = 0) -> None:
        if type(maximum_candidates) is not int or maximum_candidates < 2:
            raise ValueError("maximum_candidates must be at least two")
        if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("seed must fit uint64")
        self.maximum_candidates = maximum_candidates
        self.seed = seed
        self.feature_index_: int | None = None
        self.threshold_: float | None = None
        self.left_probability_: float | None = None
        self.right_probability_: float | None = None

    def fit(
        self,
        features: np.ndarray,
        labels: np.ndarray,
        sample_weight: np.ndarray | None = None,
    ) -> "DecisionStumpScore":
        x, y, weight = _validated_xy(features, labels, sample_weight)
        best: tuple[float, int, float, float, float] | None = None
        quantiles = np.linspace(0.0, 1.0, self.maximum_candidates + 2)[1:-1]
        for feature_index in range(x.shape[1]):
            thresholds = np.unique(np.quantile(x[:, feature_index], quantiles))
            for threshold in thresholds:
                left = x[:, feature_index] <= threshold
                if not np.any(left) or np.all(left):
                    continue
                left_weight = float(weight[left].sum())
                right_weight = float(weight[~left].sum())
                if left_weight <= 0 or right_weight <= 0:
                    continue
                left_probability = float(np.dot(weight[left], y[left]) / left_weight)
                right_probability = float(np.dot(weight[~left], y[~left]) / right_weight)
                prediction = np.where(left, left_probability, right_probability)
                loss = float(np.dot(weight, (prediction - y) ** 2) / weight.sum())
                candidate = (
                    loss,
                    feature_index,
                    float(threshold),
                    left_probability,
                    right_probability,
                )
                if best is None or candidate[:3] < best[:3]:
                    best = candidate
        if best is None:
            probability = float(np.dot(weight, y) / weight.sum())
            best = (0.0, 0, math.inf, probability, probability)
        _, self.feature_index_, self.threshold_, left, right = best
        self.left_probability_ = min(1.0, max(0.0, left))
        self.right_probability_ = min(1.0, max(0.0, right))
        return self

    def score(self, features: np.ndarray) -> np.ndarray:
        if (
            self.feature_index_ is None
            or self.threshold_ is None
            or self.left_probability_ is None
            or self.right_probability_ is None
        ):
            raise RuntimeError("model must be fitted before scoring")
        x = np.asarray(features, dtype=np.float64)
        if x.ndim != 2 or self.feature_index_ >= x.shape[1]:
            raise ValueError("feature width does not match the fitted model")
        if not np.all(np.isfinite(x)):
            raise ValueError("features must be finite")
        base = np.where(
            x[:, self.feature_index_] <= self.threshold_,
            self.left_probability_,
            self.right_probability_,
        )
        scale = 1e-9
        key = hashlib.sha256(f"public-stump-tie-break-v1:{self.seed}".encode()).digest()
        tie_break = np.empty(x.shape[0], dtype=np.float64)
        for index, row in enumerate(x):
            digest = hashlib.blake2b(row.tobytes(), key=key, digest_size=8).digest()
            tie_break[index] = int.from_bytes(digest, "big") / 2**64
        return base * (1.0 - 2.0 * scale) + scale * (1.0 + tie_break)

    @property
    def memory_bytes(self) -> int:
        return 48 if self.feature_index_ is not None else 0


class StableHashScore:
    """Untrained stable-feature hash used as the no-model routing baseline."""

    def __init__(self, seed: int) -> None:
        if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("seed must fit uint64")
        self.seed = seed
        self.feature_width_: int | None = None

    def fit(
        self,
        features: np.ndarray,
        labels: np.ndarray,
        sample_weight: np.ndarray | None = None,
    ) -> "StableHashScore":
        x, _, _ = _validated_xy(features, labels, sample_weight)
        self.feature_width_ = x.shape[1]
        return self

    def score(self, features: np.ndarray) -> np.ndarray:
        if self.feature_width_ is None:
            raise RuntimeError("model must be fitted before scoring")
        x = np.asarray(features, dtype=np.float64)
        if x.ndim != 2 or x.shape[1] != self.feature_width_:
            raise ValueError("feature width does not match the fitted model")
        if not np.all(np.isfinite(x)):
            raise ValueError("features must be finite")
        result = np.empty(x.shape[0], dtype=np.float64)
        key = hashlib.sha256(f"stable-hash-router-v1:{self.seed}".encode()).digest()
        for index, row in enumerate(x):
            digest = hashlib.blake2b(row.tobytes(), key=key, digest_size=8).digest()
            result[index] = int.from_bytes(digest, "big") / 2**64
        return result

    @property
    def memory_bytes(self) -> int:
        return 16


@dataclass(frozen=True)
class CalibratedRegionRouter:
    """A fitted score model with thresholds frozen on validation data."""

    model: ScoreModel
    thresholds: tuple[float, ...]
    calibration_sample_count: int

    def __post_init__(self) -> None:
        if type(self.thresholds) is not tuple:
            raise ValueError("router thresholds must be a tuple")
        if type(self.calibration_sample_count) is not int or self.calibration_sample_count <= 0:
            raise ValueError("calibration_sample_count must be a positive integer")
        if any(
            type(value) not in {int, float} or not math.isfinite(value) for value in self.thresholds
        ):
            raise ValueError("router thresholds must be finite")
        if tuple(self.thresholds) != tuple(sorted(self.thresholds)):
            raise ValueError("router thresholds must be sorted")

    @classmethod
    def calibrate(
        cls,
        model: ScoreModel,
        validation_features: np.ndarray,
        region_count: int,
    ) -> "CalibratedRegionRouter":
        if type(region_count) is not int or region_count <= 0:
            raise ValueError("region_count must be positive")
        scores = model.score(validation_features)
        if scores.size == 0:
            raise ValueError("validation_features must be nonempty")
        if not np.all(np.isfinite(scores)):
            raise ValueError("validation scores must be finite")
        thresholds = tuple(
            float(value)
            for value in np.quantile(
                scores,
                np.arange(1, region_count, dtype=np.float64) / region_count,
            )
        )
        return cls(model, thresholds, int(scores.size))

    def route(self, features: np.ndarray) -> np.ndarray:
        scores = self.model.score(features)
        if not np.all(np.isfinite(scores)):
            raise ValueError("router scores must be finite")
        return np.searchsorted(np.asarray(self.thresholds), scores, side="right")

    @property
    def region_count(self) -> int:
        return len(self.thresholds) + 1

    @property
    def memory_bytes(self) -> int:
        return self.model.memory_bytes + 8 * len(self.thresholds) + 24


def make_score_model(name: str, seed: int) -> ScoreModel:
    if name == "no_model":
        return StableHashScore(seed)
    if name == "logistic":
        return LogisticScore()
    if name == "small_tree":
        return DecisionStumpScore(seed=seed)
    raise ValueError(f"unsupported router model: {name}")
