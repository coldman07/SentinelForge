"""External threat and vulnerability feed loaders."""

from __future__ import annotations

import csv
import gzip
import io
import logging
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

LOG = logging.getLogger("sentinelforge.correlation.feeds")
DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


class FeedLoader:
    """Load CISA KEV, FIRST EPSS, and simple JSON IOC feeds over HTTPS."""

    def __init__(self, timeout: float = 15.0, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True)

    def load_kev(self, url: str = DEFAULT_KEV_URL) -> dict[str, dict[str, Any]]:
        response = self._client.get(url)
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, Mapping) else []
        result: dict[str, dict[str, Any]] = {}
        for item in vulnerabilities:
            if isinstance(item, Mapping) and item.get("cveID"):
                cve_id = str(item["cveID"]).upper()
                result[cve_id] = {str(k): v for k, v in item.items()}
        return result

    def load_epss(self, cves: Sequence[str], url: str = DEFAULT_EPSS_URL) -> dict[str, float]:
        unique = list(dict.fromkeys(cve.strip().upper() for cve in cves if cve.strip()))
        if not unique:
            return {}
        # FIRST documents the API for lookup batches up to 2,000 characters.
        batches: list[list[str]] = []
        batch: list[str] = []
        size = 0
        for cve in unique:
            next_size = len(cve) + (1 if batch else 0)
            if batch and size + next_size > 1900:
                batches.append(batch)
                batch, size = [], 0
                next_size = len(cve)
            batch.append(cve)
            size += next_size
        if batch:
            batches.append(batch)

        scores: dict[str, float] = {}
        for cve_batch in batches:
            response = self._client.get(url, params={"cve": ",".join(cve_batch)})
            response.raise_for_status()
            payload = response.json()
            for item in payload.get("data", []) if isinstance(payload, Mapping) else []:
                try:
                    scores[str(item["cve"]).upper()] = float(item["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        return scores

    def load_epss_csv(self, url: str = DEFAULT_EPSS_CSV_URL) -> dict[str, float]:
        """Load the complete daily EPSS CSV when bulk refresh is desired."""
        response = self._client.get(url)
        response.raise_for_status()
        content = response.content
        if content[:2] == b"\x1f\x8b":
            content = gzip.decompress(content)
        rows = (line for line in content.decode("utf-8-sig").splitlines() if line.strip() and not line.startswith("#"))
        reader = csv.DictReader(rows)
        scores: dict[str, float] = {}
        for row in reader:
            try:
                scores[str(row["cve"]).upper()] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
        return scores

    def load_ioc_json(self, url: str) -> dict[str, str]:
        """Load a JSON IOC map or a list of indicator/value records."""
        response = self._client.get(url)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, Mapping):
            entries = payload.get("indicators", payload)
            if isinstance(entries, Mapping):
                return {str(k): str(v) for k, v in entries.items() if k and v}
        if isinstance(payload, list):
            result: dict[str, str] = {}
            for item in payload:
                if not isinstance(item, Mapping):
                    continue
                indicator = item.get("indicator") or item.get("value") or item.get("ioc")
                description = item.get("description") or item.get("threat") or item.get("type") or "feed match"
                if indicator:
                    result[str(indicator)] = str(description)
            return result
        raise ValueError("IOC feed must be a JSON object or list")

    def close(self) -> None:
        self._client.close()


def load_configured_feeds(loader: FeedLoader) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """Load configured IOC feeds and KEV; log and continue when a source is unavailable."""
    import os

    threat_intel: dict[str, str] = {}
    feed_urls = [item.strip() for item in os.getenv("SF_THREAT_INTEL_URLS", "").split(",") if item.strip()]
    for url in feed_urls:
        try:
            threat_intel.update(loader.load_ioc_json(url))
        except (httpx.HTTPError, ValueError) as exc:
            LOG.warning("threat-intel feed %s unavailable: %s", url, exc)

    kev: dict[str, dict[str, Any]] = {}
    if os.getenv("SF_KEV_ENABLED", "true").strip().lower() not in {"0", "false", "no"}:
        url = os.getenv("SF_KEV_URL", DEFAULT_KEV_URL)
        try:
            kev = loader.load_kev(url)
        except (httpx.HTTPError, ValueError) as exc:
            LOG.warning("CISA KEV feed %s unavailable: %s", url, exc)
    return threat_intel, kev


__all__ = ["FeedLoader", "load_configured_feeds"]
