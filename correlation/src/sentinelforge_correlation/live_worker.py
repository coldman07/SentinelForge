"""Live JetStream enrichment and incident-correlation workers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
from collections import deque
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

import nats
from nats.errors import TimeoutError as NatsTimeoutError
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy, StreamConfig

from .correlation import CorrelationEngine
from .enrichment import EnrichmentEngine
from .feeds import FeedLoader, load_configured_feeds

LOG = logging.getLogger("sentinelforge.correlation.worker")
ALERT_STREAM = "SENTINELFORGE_ALERTS"
ALERT_SUBJECT = "sentinelforge.alerts.v1.>"
ENRICHED_STREAM = "SENTINELFORGE_ENRICHED"
ENRICHED_SUBJECT = "sentinelforge.enriched.v1.alert"
INCIDENT_STREAM = "SENTINELFORGE_INCIDENTS"
INCIDENT_SUBJECT = "sentinelforge.incidents.v1.snapshot"


async def run_worker() -> None:
    nats_url = os.getenv("SF_NATS_URL", "nats://127.0.0.1:4222")
    feed_loader = FeedLoader(timeout=float(os.getenv("SF_FEED_TIMEOUT_SECONDS", "15")))
    try:
        intel, kev = await asyncio.to_thread(load_configured_feeds, feed_loader)
        epss: dict[str, float] = {}
        engine = EnrichmentEngine(
            threat_intel=intel,
            kev=kev,
            epss=epss,
            asset_criticality=_load_asset_criticality(),
        )
        epss_url = os.getenv("SF_EPSS_URL", "https://api.first.org/data/v1/epss")
        refresh_seconds = _positive_int_env("SF_FEED_REFRESH_SECONDS", 21_600)
        last_feed_refresh = asyncio.get_running_loop().time()
        stop = asyncio.Event()
        _install_signal_handlers(stop)
        while not stop.is_set():
            connection = None
            try:
                connection = await nats.connect(
                    servers=[nats_url],
                    name="sentinelforge-enrichment-correlation",
                    max_reconnect_attempts=-1,
                    reconnect_time_wait=2,
                )
                js = connection.jetstream()
                await _ensure_stream(js, ENRICHED_STREAM, [ENRICHED_SUBJECT])
                await _ensure_stream(js, INCIDENT_STREAM, [INCIDENT_SUBJECT])
                enrich_sub = await js.pull_subscribe(
                    ALERT_SUBJECT,
                    durable=os.getenv("SF_ENRICHMENT_DURABLE_NAME", "SENTINELFORGE_ENRICHMENT"),
                    stream=ALERT_STREAM,
                    config=ConsumerConfig(
                        durable_name=os.getenv("SF_ENRICHMENT_DURABLE_NAME", "SENTINELFORGE_ENRICHMENT"),
                        deliver_policy=DeliverPolicy.ALL,
                        filter_subject=ALERT_SUBJECT,
                        ack_policy=AckPolicy.EXPLICIT,
                        ack_wait=60,
                        max_deliver=-1,
                    ),
                )
                LOG.info("consuming raw alert stream %s", ALERT_STREAM)
                last_feed_refresh = await _consume_alerts(
                    enrich_sub, js, engine, feed_loader, epss_url, last_feed_refresh,
                    refresh_seconds, stop,
                )
                incident_sub = await js.pull_subscribe(
                    ENRICHED_SUBJECT,
                    durable=os.getenv("SF_CORRELATION_DURABLE_NAME", "SENTINELFORGE_CORRELATION"),
                    stream=ENRICHED_STREAM,
                    config=ConsumerConfig(
                        durable_name=os.getenv("SF_CORRELATION_DURABLE_NAME", "SENTINELFORGE_CORRELATION"),
                        deliver_policy=DeliverPolicy.ALL,
                        filter_subject=ENRICHED_SUBJECT,
                        ack_policy=AckPolicy.EXPLICIT,
                        ack_wait=60,
                        max_deliver=-1,
                    ),
                )
                LOG.info("consuming enriched alerts from %s", ENRICHED_STREAM)
                await asyncio.gather(
                    _consume_alerts(
                        enrich_sub, js, engine, feed_loader, epss_url, last_feed_refresh,
                        refresh_seconds, stop,
                    ),
                    _consume_enriched(incident_sub, js, stop),
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception("M6 worker failed; reconnecting in five seconds")
                try:
                    await asyncio.wait_for(stop.wait(), timeout=5)
                except TimeoutError:
                    pass
            finally:
                if connection is not None:
                    await connection.close()
    finally:
        feed_loader.close()


async def _consume_alerts(subscription: Any, js: Any, engine: EnrichmentEngine,
                          loader: FeedLoader, epss_url: str, last_refresh: float,
                          refresh_seconds: int, stop: asyncio.Event) -> float:
    queried_epss: set[str] = set()
    while not stop.is_set():
        try:
            messages = await subscription.fetch(1, timeout=1)
        except NatsTimeoutError:
            continue
        for message in messages:
            try:
                envelope = json.loads(message.data)
                if not isinstance(envelope, dict):
                    await message.term()
                    continue
                now = asyncio.get_running_loop().time()
                if now - last_refresh >= refresh_seconds:
                    intel, kev = await asyncio.to_thread(load_configured_feeds, loader)
                    if intel:
                        engine.threat_intel = intel
                    if kev:
                        engine.kev = kev
                    last_refresh = now
                alert = _normalize_alert(envelope)
                cves = alert["vulnerabilities"]
                missing_cves = [
                    cve for cve in cves
                    if cve.casefold() not in {k.casefold() for k in engine.epss}
                    and cve.casefold() not in queried_epss
                ]
                if missing_cves:
                    try:
                        fresh_scores = await asyncio.to_thread(loader.load_epss, missing_cves, epss_url)
                        engine.epss.update(fresh_scores)
                        queried_epss.update(cve.casefold() for cve in missing_cves)
                    except Exception:
                        LOG.exception("EPSS lookup failed; continuing without new scores")
                enrichment = await asyncio.to_thread(engine.enrich, alert)
                event_id = str(envelope.get("event_id") or alert.get("alert_id") or "unknown")
                record = {
                    "event_id": event_id,
                    "timestamp": alert.get("timestamp") or _utc_now(),
                    "host_id": alert.get("host") or "unknown",
                    "alert": envelope,
                    "enrichment": enrichment.as_dict(),
                }
                await js.publish(
                    ENRICHED_SUBJECT,
                    json.dumps(record, separators=(",", ":"), default=str).encode("utf-8"),
                    headers={"Nats-Msg-Id": f"enriched-{event_id}"},
                )
                await message.ack_sync(timeout=5)
            except (json.JSONDecodeError, UnicodeDecodeError):
                LOG.warning("terminating malformed alert message")
                await message.term()
            except Exception:
                LOG.exception("alert enrichment failed; alert will be retried")
                await message.nak(delay=5)
    return last_refresh


async def _consume_enriched(subscription: Any, js: Any, stop: asyncio.Event) -> None:
    window = timedelta(seconds=_positive_int_env("SF_CORRELATION_WINDOW_SECONDS", 21_600))
    max_history = _positive_int_env("SF_CORRELATION_MAX_HISTORY", 5_000)
    engine = CorrelationEngine(time_window=window, max_alerts=max_history)
    history: deque[dict[str, Any]] = deque(maxlen=max_history)
    while not stop.is_set():
        try:
            messages = await subscription.fetch(1, timeout=1)
        except NatsTimeoutError:
            continue
        for message in messages:
            try:
                record = json.loads(message.data)
                if not isinstance(record, dict) or not isinstance(record.get("enrichment"), dict):
                    await message.term()
                    continue
                normalized = _correlation_alert(record)
                history.append(normalized)
                latest_time = _parse_utc(normalized.get("timestamp"))
                if latest_time is not None:
                    cutoff = latest_time - window
                    while history and (_parse_utc(history[0].get("timestamp")) or latest_time) < cutoff:
                        history.popleft()
                incidents = await asyncio.to_thread(engine.correlate, list(history))
                for incident in incidents:
                    if incident.alerts and len(incident.alerts) > 1:
                        incident_id = _stable_incident_id(incident)
                        snapshot = incident.as_dict()
                        snapshot["incident_id"] = incident_id
                        snapshot["alerts"] = incident.alerts
                        payload = {
                            "incident": snapshot,
                            "updated_at": _utc_now(),
                        }
                        await js.publish(
                            INCIDENT_SUBJECT,
                            json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"),
                            headers={"Nats-Msg-Id": f"{incident_id}-{normalized['alert_id']}"},
                        )
                await message.ack_sync(timeout=5)
            except (json.JSONDecodeError, UnicodeDecodeError):
                LOG.warning("terminating malformed enriched alert")
                await message.term()
            except Exception:
                LOG.exception("incident correlation failed; message will be retried")
                await message.nak(delay=5)


def _normalize_alert(envelope: Mapping[str, Any]) -> dict[str, Any]:
    event = envelope.get("event")
    event = event if isinstance(event, Mapping) else {}
    result = dict(event)
    result.update({key: value for key, value in envelope.items() if key not in {"event", "matches"}})
    result["alert_id"] = str(envelope.get("event_id") or event.get("event_id") or "alert-unknown")
    host = event.get("host")
    user = event.get("user")
    process = event.get("process")
    if isinstance(host, Mapping):
        result["host"] = host.get("host_id") or host.get("hostname") or host.get("name")
        result.setdefault("platform", host.get("os"))
    if isinstance(user, Mapping):
        result["user"] = user.get("name") or user.get("username")
    if isinstance(process, Mapping):
        result["image"] = process.get("path") or process.get("name")
        result["process_name"] = process.get("name")
        result["command_line"] = process.get("command_line")
    matches = envelope.get("matches") or []
    if isinstance(matches, Mapping):
        matches = [matches]
    if matches:
        result["title"] = "; ".join(str(item.get("title") or item.get("rule_id") or "Detection")
                                      for item in matches if isinstance(item, Mapping))
        levels = [str(item.get("level", "low")).lower() for item in matches if isinstance(item, Mapping)]
        result["severity"] = max(levels, key=lambda value: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(value, 0))
        result["techniques"] = [tag for item in matches if isinstance(item, Mapping)
                                for tag in (item.get("tags") or []) if isinstance(tag, str)]
        result["rule_id"] = ",".join(str(item.get("rule_id")) for item in matches
                                     if isinstance(item, Mapping) and item.get("rule_id"))
    result["timestamp"] = event.get("timestamp") or envelope.get("timestamp")
    return result


def _correlation_alert(record: Mapping[str, Any]) -> dict[str, Any]:
    enrichment = record["enrichment"]
    original = record.get("alert") or {}
    normalized = _normalize_alert(original if isinstance(original, Mapping) else {})
    normalized.update({
        "alert_id": record.get("event_id") or enrichment.get("alert_id"),
        "timestamp": record.get("timestamp") or normalized.get("timestamp"),
        "score": enrichment.get("score", 0),
        "severity": enrichment.get("severity", normalized.get("severity", "low")),
        "asset_criticality": enrichment.get("asset_criticality", "low"),
        "tactics": enrichment.get("tactics", []),
        "techniques": enrichment.get("techniques", []),
        "entities": [normalized.get(key) for key in ("host", "user", "source_ip", "destination_ip") if normalized.get(key)],
    })
    return normalized


def _stable_incident_id(incident: Any) -> str:
    earliest = min(
        incident.alerts,
        key=lambda alert: _parse_utc(alert.get("timestamp")) or datetime.max.replace(tzinfo=timezone.utc),
    )
    seed = str(earliest.get("alert_id", ""))
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"INC-{digest}"


async def _ensure_stream(js: Any, name: str, subjects: list[str]) -> None:
    try:
        info = await js.stream_info(name)
    except Exception:
        await js.add_stream(StreamConfig(name=name, subjects=subjects))
        return
    existing = set(info.config.subjects or [])
    if not set(subjects).issubset(existing):
        await js.update_stream(StreamConfig(name=name, subjects=sorted(existing | set(subjects))))


def _load_asset_criticality() -> dict[str, str]:
    raw = os.getenv("SF_ASSET_CRITICALITY_JSON") or "{}"
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SF_ASSET_CRITICALITY_JSON must be a JSON object") from exc
    if not isinstance(values, dict):
        raise ValueError("SF_ASSET_CRITICALITY_JSON must be a JSON object")
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in values.items()}


def _parse_utc(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for stop_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(stop_signal, stop.set)
        except (NotImplementedError, RuntimeError):
            pass


def main() -> int:
    logging.basicConfig(level=os.getenv("SF_LOG_LEVEL", "INFO"))
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        return 130
    return 0


__all__ = ["run_worker", "main"]
