"""Explainable UEBA primitives for SentinelForge event envelopes."""

from .scorer import BaselineScorer, FeatureExplanation, ScoreResult
from .evaluation import EvaluationMetrics, LabeledEvent, evaluate_labeled_events

__all__ = [
    "BaselineScorer",
    "EvaluationMetrics",
    "FeatureExplanation",
    "LabeledEvent",
    "ScoreResult",
    "evaluate_labeled_events",
]
