"""Narrow read-only tools for retrieving SentinelForge evidence."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

import httpx


class ReadOnlyEvidenceTools:
    """Expose only bounded GET access to the gateway's event and alert APIs."""

    def __init__(self, gateway_url: str, timeout: float = 10.0, client: httpx.Client | None = None) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.client = client or httpx.Client(timeout=timeout)
        self.calls: list[dict[str, Any]] = []

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._get_records("events", limit)

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._get_records("alerts", limit)

    def recent_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._get_records("incidents", limit)

    def retrieve_evidence(self, question: str, *, host_id: str | None = None,
                          event_id: str | None = None, incident_id: str | None = None,
                          limit: int = 100) -> list[dict[str, Any]]:
        """Search a bounded recent window locally; the gateway accepts no write/query DSL."""
        limit = max(1, min(int(limit), 100))
        events = self.recent_events(limit)
        alerts = self.recent_alerts(limit)
        incidents = self.recent_incidents(limit)
        if incident_id:
            events = []
            alerts = []
        terms = {term.casefold() for term in question.split() if len(term) > 2}
        results: list[dict[str, Any]] = []
        for kind, records in (("event", events), ("alert", alerts)):
            for record in records:
                identifier = str(record.get("event_id") or "")
                record_host = str(record.get("host_id") or "")
                if event_id and identifier != event_id:
                    continue
                if host_id and record_host.casefold() != host_id.casefold():
                    continue
                serialized = json.dumps(record, sort_keys=True, default=str)
                if terms and not any(term in serialized.casefold() for term in terms):
                    if event_id is None and not host_id:
                        continue
                results.append({"kind": kind, "event_id": identifier, "record": record})
        for record in incidents:
            current_incident_id = str(record.get("incident_id") or "")
            if incident_id and current_incident_id != incident_id:
                continue
            raw_incident = record.get("incident")
            if not isinstance(raw_incident, Mapping):
                continue
            snapshot = raw_incident.get("incident")
            snapshot = snapshot if isinstance(snapshot, Mapping) else raw_incident
            serialized = json.dumps(record, sort_keys=True, default=str).casefold()
            if host_id and str(host_id).casefold() not in serialized:
                continue
            if event_id and event_id not in serialized:
                continue
            if not incident_id and not event_id and not host_id and terms and not any(term in serialized for term in terms):
                continue
            for alert in snapshot.get("alerts", []) if isinstance(snapshot, Mapping) else []:
                if not isinstance(alert, Mapping):
                    continue
                alert_event_id = str(alert.get("alert_id") or alert.get("event_id") or "")
                if not alert_event_id:
                    continue
                if event_id and alert_event_id != event_id:
                    continue
                results.append({
                    "kind": "incident",
                    "event_id": alert_event_id,
                    "incident_id": current_incident_id,
                    "record": {"incident": snapshot, "alert": alert},
                })
        return results

    def _get_records(self, resource: str, limit: int) -> list[dict[str, Any]]:
        if resource not in {"events", "alerts", "incidents"}:
            raise ValueError("unsupported read-only resource")
        bounded_limit = max(1, min(int(limit), 100))
        response = self.client.get(
            f"{self.gateway_url}/v1/{resource}",
            params={"limit": bounded_limit},
            headers=(
                {"Authorization": f"Bearer {os.environ['SF_INTERNAL_API_BEARER_TOKEN']}"}
                if os.getenv("SF_INTERNAL_API_BEARER_TOKEN")
                else None
            ),
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError(f"gateway returned an invalid {resource} response")
        self.calls.append({"tool": f"recent_{resource}", "limit": bounded_limit, "count": len(payload)})
        return [dict(item) for item in payload if isinstance(item, Mapping)]

    def close(self) -> None:
        self.client.close()


__all__ = ["ReadOnlyEvidenceTools"]
