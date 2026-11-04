"""A minimal attack-chain correlation engine for SentinelForge alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping


def _flatten_strings(value: Any) -> list[str]:
    """Normalize a scalar or collection into a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        flattened: list[str] = []
        for item in value:
            flattened.extend(_flatten_strings(item))
        return flattened
    return [str(value)]


@dataclass(slots=True)
class AlertCluster:
    """A temporal cluster of related alerts."""

    alerts: list[dict[str, Any]] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)
    tactics: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    score: float = 0.0

    def add_alert(self, alert: Mapping[str, Any]) -> None:
        alert_dict = dict(alert)
        self.alerts.append(alert_dict)
        for key in ("host", "hostname", "user", "username", "source_ip", "destination_ip", "process_name", "image"):
            value = alert_dict.get(key)
            if value not in (None, ""):
                self.entities.add(str(value))
        tactic_values = _flatten_strings(alert_dict.get("tactics"))
        tactic_values.extend(_flatten_strings(alert_dict.get("techniques")))
        self.tactics.extend(item for item in tactic_values if item not in (None, ""))
        self.tactics = list(dict.fromkeys(self.tactics))

        event_time = _parse_time(alert_dict.get("timestamp") or alert_dict.get("occurred_at") or alert_dict.get("time"))
        if event_time is not None:
            if self.first_seen is None or event_time < self.first_seen:
                self.first_seen = event_time
            if self.last_seen is None or event_time > self.last_seen:
                self.last_seen = event_time

        self.score += float(alert_dict.get("score", 0) or 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_count": len(self.alerts),
            "entities": sorted(self.entities),
            "tactics": list(self.tactics),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "score": self.score,
        }


@dataclass(slots=True)
class Incident:
    """A grouped incident containing correlated alerts."""

    incident_id: str
    title: str
    alerts: list[dict[str, Any]] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)
    tactics: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    severity: str = "low"
    score: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "alert_count": len(self.alerts),
            "entities": sorted(self.entities),
            "tactics": list(self.tactics),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "severity": self.severity,
            "score": self.score,
        }


class CorrelationEngine:
    """Cluster related alerts into incidents using a time window and shared entities."""

    def __init__(self, time_window: timedelta = timedelta(hours=6), max_alerts: int = 25) -> None:
        self.time_window = time_window
        self.max_alerts = max_alerts

    def _alert_time(self, alert: Mapping[str, Any]) -> datetime | None:
        return _parse_time(alert.get("timestamp") or alert.get("occurred_at") or alert.get("time"))

    def _entity_keys(self, alert: Mapping[str, Any]) -> set[str]:
        keys = {
            str(alert.get(key))
            for key in ("host", "hostname", "user", "username", "source_ip", "destination_ip", "process_name", "image")
            if alert.get(key) not in (None, "")
        }
        return keys

    def correlate(self, alerts: Iterable[Mapping[str, Any]]) -> list[Incident]:
        sorted_alerts = sorted(
            (dict(alert) for alert in alerts),
            key=lambda alert: _parse_time(alert.get("timestamp") or alert.get("occurred_at") or alert.get("time")) or datetime.min,
        )

        clusters: list[AlertCluster] = []
        for alert in sorted_alerts:
            event_time = self._alert_time(alert)
            matched = None
            for cluster in clusters:
                if event_time is None or cluster.last_seen is None:
                    continue
                if event_time - cluster.last_seen > self.time_window:
                    continue
                shared = self._entity_keys(alert) & cluster.entities
                if shared:
                    matched = cluster
                    break
            if matched is None:
                cluster = AlertCluster()
                cluster.add_alert(alert)
                clusters.append(cluster)
            else:
                matched.add_alert(alert)

        incidents: list[Incident] = []
        for index, cluster in enumerate(clusters, start=1):
            if not cluster.alerts:
                continue
            if len(cluster.alerts) > self.max_alerts:
                cluster.alerts = cluster.alerts[: self.max_alerts]
            tactics = list(dict.fromkeys(cluster.tactics))
            severity = "low"
            if any(alert.get("severity") in {"critical", "high", "sev0", "sev1"} for alert in cluster.alerts):
                severity = "critical" if any(alert.get("severity") in {"critical", "sev0"} for alert in cluster.alerts) else "high"
            elif any(alert.get("severity") in {"medium", "sev2"} for alert in cluster.alerts):
                severity = "medium"
            score = sum(float(alert.get("score", 0) or 0) for alert in cluster.alerts)
            incident = Incident(
                incident_id=f"INC-{index:04d}",
                title=f"Correlated activity on {sorted(cluster.entities)[:2] or ['unknown']}",
                alerts=cluster.alerts,
                entities=set(cluster.entities),
                tactics=tactics,
                first_seen=cluster.first_seen,
                last_seen=cluster.last_seen,
                severity=severity,
                score=score,
            )
            incidents.append(incident)
        return incidents


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    text = str(value).strip()
    if not text:
        return None
    for candidate in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = datetime.strptime(text, candidate)
            if parsed.tzinfo is not None:
                return parsed.astimezone().replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    try:
        from datetime import timezone

        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


__all__ = ["AlertCluster", "Incident", "CorrelationEngine"]
