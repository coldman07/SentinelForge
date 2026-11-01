"""Offline confusion-matrix metrics for labeled UEBA event samples."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import isfinite
from typing import Any, Iterable, Mapping

from .scorer import BaselineScorer


@dataclass(frozen=True, slots=True)
class LabeledEvent:
    """An event and its expected anomaly label."""

    event: Mapping[str, Any]
    anomalous: bool


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    """Confusion counts and readiness-aware classification metrics."""

    threshold: float
    total: int
    ready: int
    unready: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def precision(self) -> float | None:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else None

    @property
    def false_positive_rate(self) -> float | None:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else None

    @property
    def accuracy(self) -> float | None:
        denominator = (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
        )
        correct = self.true_positive + self.true_negative
        return correct / denominator if denominator else None

    @property
    def readiness_coverage(self) -> float | None:
        return self.ready / self.total if self.total else None

    def to_dict(self) -> dict[str, Any]:
        """Return counts and derived metrics in JSON-compatible form."""
        result = asdict(self)
        result.update(
            precision=self.precision,
            recall=self.recall,
            false_positive_rate=self.false_positive_rate,
            accuracy=self.accuracy,
            readiness_coverage=self.readiness_coverage,
        )
        return result


def evaluate_labeled_events(
    scorer: BaselineScorer,
    samples: Iterable[LabeledEvent],
    *,
    threshold: float | None = None,
) -> EvaluationMetrics:
    """Evaluate fixed labels without updating scorer baselines.

    Unready events cannot raise an alert and are counted as negative
    predictions. ``readiness_coverage`` makes that limitation visible instead
    of silently presenting those results as baseline-backed scores.
    """
    if threshold is not None and (
        isinstance(threshold, bool) or not isinstance(threshold, (int, float))
    ):
        raise ValueError("threshold must be numeric")
    cutoff = scorer.anomaly_threshold if threshold is None else float(threshold)
    if not isfinite(cutoff) or not 0.0 <= cutoff <= 100.0:
        raise ValueError("threshold must be a finite value between 0 and 100")

    total = ready = tp = fp = tn = fn = 0
    for sample in samples:
        if not isinstance(sample.anomalous, bool):
            raise ValueError("each labeled event must use a boolean anomaly label")
        total += 1
        result = scorer.score_event(sample.event)
        ready += int(result.ready)
        prediction = bool(
            result.ready and result.score is not None and result.score >= cutoff
        )
        if sample.anomalous and prediction:
            tp += 1
        elif sample.anomalous:
            fn += 1
        elif prediction:
            fp += 1
        else:
            tn += 1

    return EvaluationMetrics(
        threshold=cutoff,
        total=total,
        ready=ready,
        unready=total - ready,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )
