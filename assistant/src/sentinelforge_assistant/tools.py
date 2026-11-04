"""Narrow read-only tools for retrieving SentinelForge evidence."""

from __future__ import annotations

import json
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

    def retrieve_evidence(self, question: str, *, host_id: str | None = None,
                          event_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Search a bounded recent window locally; the gateway accepts no write/query DSL."""
        limit = max(1, min(int(limit), 100))
        events = self.recent_events(limit)
        alerts = self.recent_alerts(limit)
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
        return results

    def _get_records(self, resource: str, limit: int) -> list[dict[str, Any]]:
        if resource not in {"events", "alerts"}:
            raise ValueError("unsupported read-only resource")
        bounded_limit = max(1, min(int(limit), 100))
        response = self.client.get(
            f"{self.gateway_url}/v1/{resource}", params={"limit": bounded_limit}
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
