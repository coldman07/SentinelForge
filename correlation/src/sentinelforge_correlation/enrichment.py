"""Alert enrichment and alert scoring for SentinelForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping


def _coerce_severity(value: Any) -> str:
    if value is None:
        return "low"
    normalized = str(value).strip().lower()
    if normalized in {"critical", "sev0", "sev-0", "0"}:
        return "critical"
    if normalized in {"high", "sev1", "sev-1", "1"}:
        return "high"
    if normalized in {"medium", "moderate", "sev2", "sev-2", "2"}:
        return "medium"
    if normalized in {"low", "info", "informational", "sev3", "sev-3", "3"}:
        return "low"
    return "low"


@dataclass(slots=True)
class EnrichedAlert:
    """Alert payload after enrichment and scoring."""

    alert_id: str
    rule_id: str | None = None
    title: str | None = None
    severity: str = "low"
    score: float = 0.0
    asset_criticality: str = "low"
    indicator_matches: list[str] = field(default_factory=list)
    threat_intel: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "asset_criticality": self.asset_criticality,
            "indicator_matches": list(self.indicator_matches),
            "threat_intel": list(self.threat_intel),
            "vulnerabilities": list(self.vulnerabilities),
            "tactics": list(self.tactics),
            "evidence": dict(self.evidence),
            "raw": dict(self.raw),
        }


class EnrichmentEngine:
    """Apply threat-intel, vulnerability, asset and risk scoring enrichment."""

    def __init__(
        self,
        threat_intel: Mapping[str, str] | None = None,
        kev: Mapping[str, dict[str, Any]] | None = None,
        epss: Mapping[str, float] | None = None,
        asset_criticality: Mapping[str, str] | None = None,
    ) -> None:
        self.threat_intel = dict(threat_intel or {})
        self.kev = dict(kev or {})
        self.epss = dict(epss or {})
        self.asset_criticality = {
            "prod": "high",
            "production": "high",
            "critical": "critical",
            "domain": "medium",
            "db": "high",
            "server": "high",
            "workstation": "medium",
            "desktop": "medium",
            "laptop": "medium",
            "unknown": "low",
            **(asset_criticality or {}),
        }

    def _value_for_keys(self, alert: Mapping[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in alert and alert[key] not in (None, ""):
                return alert[key]
        return None

    def _candidate_iocs(self, alert: Mapping[str, Any]) -> list[str]:
        values: list[str] = []
        for key in (
            "host",
            "hostname",
            "user",
            "username",
            "source_ip",
            "src_ip",
            "destination_ip",
            "dst_ip",
            "ip",
            "domain",
            "hash",
            "sha256",
            "md5",
            "parent_image",
            "image",
        ):
            value = self._value_for_keys(alert, key)
            if value is None:
                continue
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    if item not in (None, ""):
                        values.append(str(item))
            else:
                values.append(str(value))
        return values

    def _risk_weight(self, severity: str) -> int:
        return {"critical": 50, "high": 35, "medium": 20, "low": 10}.get(severity.lower(), 10)

    def enrich(self, alert: Mapping[str, Any] | Any) -> EnrichedAlert:
        if not isinstance(alert, Mapping):
            raise TypeError("alert must be a mapping")

        alert_id = str(self._value_for_keys(alert, "alert_id", "id", "event_id") or "alert-unknown")
        rule_id = self._value_for_keys(alert, "rule_id", "rule", "signature")
        title = self._value_for_keys(alert, "title", "name", "rule_name")
        severity = _coerce_severity(self._value_for_keys(alert, "severity", "level", "priority"))
        asset_context = self._value_for_keys(alert, "asset_class", "asset", "host_role", "platform")
        asset_criticality = self.asset_criticality.get(str(asset_context).lower(), "low") if asset_context else "low"

        iocs = []
        threat_intel = []
        for candidate in self._candidate_iocs(alert):
            if candidate in self.threat_intel:
                entry = self.threat_intel[candidate]
                iocs.append(candidate)
                threat_intel.append(entry)
            elif candidate.lower() in {key.lower() for key in self.threat_intel}:
                key = next(key for key in self.threat_intel if key.lower() == candidate.lower())
                iocs.append(candidate)
                threat_intel.append(self.threat_intel[key])

        vulnerabilities: list[str] = []
        if "vulnerabilities" in alert:
            for item in alert["vulnerabilities"] or []:
                if isinstance(item, str):
                    vulnerabilities.append(item)
                elif isinstance(item, Mapping):
                    vuln_id = item.get("id") or item.get("cve") or item.get("name")
                    if vuln_id:
                        vulnerabilities.append(str(vuln_id))
        if "cve" in alert:
            vulnerabilities.append(str(alert["cve"]))

        score = self._risk_weight(severity) + (len(iocs) * 10) + (len(vulnerabilities) * 7)
        if asset_criticality in {"medium", "high", "critical"}:
            score += {"medium": 5, "high": 10, "critical": 15}[asset_criticality]

        tactics = []
        for key in ("tactics", "mitre_tactics", "attack_tactics", "techniques"):
            if key in alert:
                value = alert[key]
                if isinstance(value, str):
                    tactics.append(value)
                elif isinstance(value, Iterable):
                    for item in value:
                        tactics.append(str(item))

        enriched = EnrichedAlert(
            alert_id=str(alert_id),
            rule_id=str(rule_id) if rule_id is not None else None,
            title=str(title) if title is not None else None,
            severity=severity,
            score=float(score),
            asset_criticality=asset_criticality,
            indicator_matches=list(dict.fromkeys(iocs)),
            threat_intel=list(dict.fromkeys(threat_intel)),
            vulnerabilities=list(dict.fromkeys(vulnerabilities)),
            tactics=list(dict.fromkeys(tactics)),
            evidence={
                "severity": severity,
                "asset_criticality": asset_criticality,
                "indicator_matches": list(dict.fromkeys(iocs)),
                "vulnerabilities": list(dict.fromkeys(vulnerabilities)),
                "observed_at": datetime.utcnow().isoformat(timespec="seconds"),
            },
            raw=dict(alert),
        )
        return enriched

    def enrich_many(self, alerts: Iterable[Mapping[str, Any]]) -> list[EnrichedAlert]:
        return [self.enrich(alert) for alert in alerts]


__all__ = ["EnrichedAlert", "EnrichmentEngine"]
