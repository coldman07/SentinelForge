"""Online categorical baselines and explainable rarity scores.

The scorer consumes the JSON event envelope defined in
``proto/events/v1/event.proto``. Baselines are in memory; callers should seed
them with known-good telemetry via :meth:`BaselineScorer.learn_event` before
scoring a live stream.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from math import log
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

_SMOOTHING = 0.5


@dataclass(frozen=True, slots=True)
class FeatureExplanation:
    """A feature's contribution to an event's anomaly score."""

    scope: str
    feature: str
    value: str
    score: float
    observed_count: int
    observation_count: int


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """An explainable result for one event."""

    event_id: str
    score: float | None
    anomalous: bool
    ready: bool
    observations_remaining: int
    explanations: tuple[FeatureExplanation, ...]
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible result for an alert or API response."""
        return {
            "event_id": self.event_id,
            "score": self.score,
            "anomalous": self.anomalous,
            "ready": self.ready,
            "observations_remaining": self.observations_remaining,
            "explanations": [asdict(item) for item in self.explanations],
            "reason": self.reason,
        }


class BaselineScorer:
    """Learn per-host and per-user categorical baselines without dependencies.

    ``observe_event`` scores before updating and suppresses baseline updates
    for high-scoring events after warm-up. Use ``learn_event`` only for a
    trusted baseline window, then switch to ``observe_event`` for live data.
    """

    def __init__(
        self,
        *,
        warmup_observations: int = 25,
        anomaly_threshold: float = 65.0,
        max_values_per_feature: int = 2048,
        explanation_limit: int = 5,
    ) -> None:
        if warmup_observations < 1:
            raise ValueError("warmup_observations must be at least 1")
        if not 0.0 <= anomaly_threshold <= 100.0:
            raise ValueError("anomaly_threshold must be between 0 and 100")
        if max_values_per_feature < 2:
            raise ValueError("max_values_per_feature must be at least 2")
        if explanation_limit < 1:
            raise ValueError("explanation_limit must be at least 1")

        self.warmup_observations = warmup_observations
        self.anomaly_threshold = anomaly_threshold
        self.max_values_per_feature = max_values_per_feature
        self.explanation_limit = explanation_limit
        self._counts: dict[tuple[str, str], Counter[str]] = {}
        self._feature_observation_counts: Counter[tuple[str, str]] = Counter()
        self._observation_counts: Counter[str] = Counter()

    def learn_event(self, event: Mapping[str, Any]) -> None:
        """Add a trusted event to its host and user baselines."""
        features = _extract_features(event)
        for scope, values in features.items():
            self._observation_counts[scope] += 1
            for feature, value in values.items():
                feature_key = (scope, feature)
                self._feature_observation_counts[feature_key] += 1
                counts = self._counts.setdefault(feature_key, Counter())
                if value in counts or len(counts) < self.max_values_per_feature:
                    counts[value] += 1

    def score_event(self, event: Mapping[str, Any]) -> ScoreResult:
        """Score an event against existing baselines without changing them."""
        event_id = _string(event.get("event_id")) or "unknown"
        features = _extract_features(event)
        if not features:
            return ScoreResult(
                event_id, None, False, False, self.warmup_observations, (),
                "event has no usable host identity or supported features",
            )

        host_scope = next((scope for scope in features if scope.startswith("host:")), None)
        host_observations = self._observation_counts[host_scope] if host_scope else 0
        ready = host_observations >= self.warmup_observations
        remaining = max(0, self.warmup_observations - host_observations)
        explanations: list[FeatureExplanation] = []

        for scope, values in features.items():
            scope_ready = self._observation_counts[scope] >= self.warmup_observations
            if ready and not scope_ready:
                continue
            for feature, value in values.items():
                counts = self._counts.get((scope, feature), Counter())
                observation_count = self._feature_observation_counts[(scope, feature)]
                observed_count = counts.get(value, 0)
                cardinality = max(1, len(counts))
                probability = (observed_count + _SMOOTHING) / (
                    observation_count + _SMOOTHING * (cardinality + 1)
                )
                denominator = log(observation_count + cardinality + 1)
                surprise = min(1.0, -log(probability) / denominator) if denominator > 0 else 1.0
                explanations.append(
                    FeatureExplanation(
                        scope=scope,
                        feature=feature,
                        value=value,
                        score=round(surprise * 100.0, 2),
                        observed_count=observed_count,
                        observation_count=observation_count,
                    )
                )

        explanations.sort(key=lambda item: item.score, reverse=True)
        if not explanations:
            return ScoreResult(
                event_id, None, False, ready, remaining, (),
                "no entity baseline is ready for these features",
            )
        feature_scores = [item.score for item in explanations]
        average_score = sum(feature_scores) / len(feature_scores)
        score = round(0.5 * max(feature_scores) + 0.5 * average_score, 2)
        return ScoreResult(
            event_id=event_id,
            score=score,
            anomalous=ready and score >= self.anomaly_threshold,
            ready=ready,
            observations_remaining=remaining,
            explanations=tuple(explanations[: self.explanation_limit]),
            reason=None if ready else "host baseline is warming up",
        )

    def observe_event(self, event: Mapping[str, Any]) -> ScoreResult:
        """Score an event, then learn it only during warm-up or below threshold."""
        result = self.score_event(event)
        if result.score is None:
            return result
        if not result.ready or result.score < self.anomaly_threshold:
            self.learn_event(event)
        return result

    def baseline_size(self, scope: str | None = None) -> int:
        """Return learned event counts, optionally for one exact entity scope."""
        if scope is not None:
            return self._observation_counts[scope]
        return sum(self._observation_counts.values())

    def save(self, path: str | Path) -> None:
        """Atomically save this baseline as a versioned JSON document."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format_version": 1,
            "config": {
                "warmup_observations": self.warmup_observations,
                "anomaly_threshold": self.anomaly_threshold,
                "max_values_per_feature": self.max_values_per_feature,
                "explanation_limit": self.explanation_limit,
            },
            "observation_counts": dict(self._observation_counts),
            "features": [
                {
                    "scope": scope,
                    "feature": feature,
                    "observation_count": self._feature_observation_counts[(scope, feature)],
                    "values": dict(counts),
                }
                for (scope, feature), counts in sorted(self._counts.items())
            ],
        }
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(payload, temporary_file, ensure_ascii=False, sort_keys=True)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, destination)
        except BaseException:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise

    @classmethod
    def load(cls, path: str | Path) -> BaselineScorer:
        """Load a versioned baseline JSON document, rejecting malformed data."""
        with Path(path).open(encoding="utf-8") as baseline_file:
            payload = json.load(baseline_file)
        if (
            not isinstance(payload, dict)
            or type(payload.get("format_version")) is not int
            or payload["format_version"] != 1
        ):
            raise ValueError("unsupported or invalid UEBA baseline format")

        config = payload.get("config")
        observations = payload.get("observation_counts")
        features = payload.get("features")
        if not isinstance(config, dict) or not isinstance(observations, dict):
            raise ValueError("UEBA baseline is missing config or observation counts")
        if not isinstance(features, list):
            raise ValueError("UEBA baseline features must be a list")
        scorer = cls(
            warmup_observations=_positive_int(config.get("warmup_observations")),
            anomaly_threshold=_threshold(config.get("anomaly_threshold")),
            max_values_per_feature=_positive_int(config.get("max_values_per_feature"), minimum=2),
            explanation_limit=_positive_int(config.get("explanation_limit")),
        )

        for scope, count in observations.items():
            if not isinstance(scope, str) or not scope or not _nonnegative_int(count):
                raise ValueError("invalid scope observation count in UEBA baseline")
            scorer._observation_counts[scope] = count

        for item in features:
            if not isinstance(item, dict):
                raise ValueError("invalid feature entry in UEBA baseline")
            scope = item.get("scope")
            feature = item.get("feature")
            observation_count = item.get("observation_count")
            values = item.get("values")
            if (
                not isinstance(scope, str)
                or not scope
                or not isinstance(feature, str)
                or not feature
                or not _positive_int(observation_count)
                or not isinstance(values, dict)
                or len(values) > scorer.max_values_per_feature
            ):
                raise ValueError("invalid feature entry in UEBA baseline")
            if any(
                not isinstance(value, str) or not value or not _positive_int(count)
                for value, count in values.items()
            ):
                raise ValueError("invalid feature value count in UEBA baseline")
            if sum(values.values()) > observation_count:
                raise ValueError("feature value counts exceed observations")
            if observation_count > scorer._observation_counts.get(scope, 0):
                raise ValueError("feature observations exceed scope observations")
            feature_key = (scope, feature)
            if feature_key in scorer._counts:
                raise ValueError("duplicate feature entry in UEBA baseline")
            scorer._counts[feature_key] = Counter(values)
            scorer._feature_observation_counts[feature_key] = observation_count
        return scorer


def _extract_features(event: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    host = event.get("host")
    host_id = _string(host.get("host_id")) if isinstance(host, Mapping) else ""
    if not host_id:
        return {}

    category = _string(event.get("category")).casefold()
    details = event.get(category)
    if not isinstance(details, Mapping):
        details = {}
    host_features: dict[str, str] = {
        "event.category": category or "unknown",
        "event.action": f"{category}:{_string(event.get('action')).casefold() or 'unknown'}",
    }
    user_features: dict[str, str] = {}

    user = event.get("user")
    username = _string(user.get("name")) if isinstance(user, Mapping) else ""

    if category == "process":
        image = _normalise_path(_string(details.get("path")) or _string(details.get("name")))
        if image:
            host_features["process.image"] = image
            user_features["process.image"] = image
        parent = details.get("parent")
        if isinstance(parent, Mapping):
            parent_name = _string(parent.get("name")) or f"pid:{_string(parent.get('pid'))}"
            child_name = _string(details.get("name")) or image
            if child_name:
                host_features["process.parent_child"] = (
                    f"{parent_name.casefold()}->{child_name.casefold()}"
                )
    elif category == "file":
        path = _string(details.get("path"))
        basename = path.replace("\\", "/").rsplit("/", 1)[-1]
        extension = basename.rsplit(".", 1)[-1].casefold() if "." in basename else "none"
        host_features["file.action"] = _string(event.get("action")).casefold() or "unknown"
        host_features["file.extension"] = extension
    elif category == "network":
        protocol = _string(details.get("protocol")).casefold() or "unknown"
        remote_address = _string(details.get("remote_address")).casefold()
        remote_port = _string(details.get("remote_port"))
        if remote_address:
            host_features["network.destination"] = remote_address
            user_features["network.destination"] = remote_address
        if remote_port:
            host_features["network.destination_port"] = f"{protocol}:{remote_port}"
    elif category == "authentication":
        username = username or _string(details.get("target"))
        method = _string(details.get("method")).casefold()
        source = _string(details.get("source_address")).casefold()
        outcome = _string(details.get("outcome")).casefold()
        if method:
            host_features["authentication.method"] = method
            user_features["authentication.method"] = method
        if source:
            host_features["authentication.source"] = source
            user_features["authentication.source"] = source
        if outcome:
            host_features["authentication.outcome"] = outcome
            user_features["authentication.outcome"] = outcome

    hour = _utc_hour(_string(event.get("timestamp")))
    if hour is not None:
        host_features["time.utc_hour"] = f"{hour:02d}"
        user_features["time.utc_hour"] = f"{hour:02d}"

    features = {f"host:{host_id.casefold()}": host_features}
    if username:
        features[f"user:{username.casefold()}"] = user_features or host_features.copy()
    return features


def _utc_hour(timestamp: str) -> int | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc).hour
    return parsed.astimezone(timezone.utc).hour


def _normalise_path(path: str) -> str:
    return path.strip().replace("/", "\\").casefold()


def _string(value: Any) -> str:
    if value is None or isinstance(value, (dict, list, tuple)):
        return ""
    return str(value).strip()


def _positive_int(value: Any, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("baseline configuration and counters must be valid integers")
    return value


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _threshold(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("baseline anomaly threshold must be numeric")
    threshold = float(value)
    if not 0.0 <= threshold <= 100.0:
        raise ValueError("baseline anomaly threshold must be between 0 and 100")
    return threshold
