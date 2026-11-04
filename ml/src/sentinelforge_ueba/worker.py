"""JetStream consumer that evaluates events and publishes UEBA alerts."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import ssl
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import nats
from nats.errors import TimeoutError as NatsTimeoutError
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

from .scorer import BaselineScorer, ScoreResult

EVENT_STREAM = "SENTINELFORGE_EVENTS"
EVENT_SUBJECT = "sentinelforge.events.v1.>"
ALERT_SUBJECT = "sentinelforge.alerts.v1.match"
DEFAULT_DURABLE = "SENTINELFORGE_UEBA"
LOG = logging.getLogger("sentinelforge.ueba")


def _nats_tls() -> ssl.SSLContext | None:
    if os.getenv("SF_MTLS_REQUIRED", "false").lower() != "true":
        return None
    ca, cert, key = (os.getenv(name) for name in ("SF_NATS_CA_FILE", "SF_NATS_CERT_FILE", "SF_NATS_KEY_FILE"))
    if not all((ca, cert, key)):
        raise RuntimeError("SF_MTLS_REQUIRED needs SF_NATS_CA_FILE, SF_NATS_CERT_FILE, and SF_NATS_KEY_FILE")
    context = ssl.create_default_context(cafile=ca)
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


async def run_worker() -> None:
    """Connect to JetStream, score events, and publish alert evidence."""
    nats_url = os.getenv("SF_NATS_URL", "nats://127.0.0.1:4222")
    baseline_path = Path(os.getenv("SF_UEBA_BASELINE_PATH", "data/ueba-baseline.json"))
    durable = os.getenv("SF_UEBA_DURABLE_NAME", DEFAULT_DURABLE)
    batch_size = _positive_int_env("SF_UEBA_BATCH_SIZE", 16)
    checkpoint_size = _positive_int_env("SF_UEBA_CHECKPOINT_SIZE", 32)
    scorer, seeded_baseline = _load_scorer(baseline_path)
    pending_acks: list[Any] = []
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for stop_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(stop_signal, stopping.set)
        except NotImplementedError:
            pass

    LOG.info(
        "UEBA worker starting (baseline=%s, durable=%s, nats=%s)",
        baseline_path,
        durable,
        nats_url,
    )
    while not stopping.is_set():
        connection = None
        try:
            connection = await nats.connect(
                servers=[nats_url],
                name="sentinelforge-ueba",
                max_reconnect_attempts=-1,
                reconnect_time_wait=2,
                tls=_nats_tls(),
            )
            jetstream = connection.jetstream()
            consumer_config = ConsumerConfig(
                durable_name=durable,
                deliver_policy=DeliverPolicy.ALL if seeded_baseline else DeliverPolicy.NEW,
                filter_subject=EVENT_SUBJECT,
                ack_policy=AckPolicy.EXPLICIT,
                ack_wait=300,
                max_deliver=-1,
                max_ack_pending=max(batch_size, checkpoint_size),
            )
            subscription = await jetstream.pull_subscribe(
                EVENT_SUBJECT,
                durable=durable,
                stream=EVENT_STREAM,
                config=consumer_config,
            )
            LOG.info("consuming %s with durable consumer %s", EVENT_STREAM, durable)
            await _consume(
                subscription,
                jetstream,
                scorer,
                baseline_path,
                pending_acks,
                stopping,
                batch_size,
                checkpoint_size,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("UEBA JetStream worker failed; reconnecting in five seconds")
            try:
                await _flush_pending(scorer, baseline_path, pending_acks)
            except Exception:
                LOG.exception("could not checkpoint UEBA state before reconnecting")
            try:
                await asyncio.wait_for(stopping.wait(), timeout=5)
            except TimeoutError:
                pass
        finally:
            if connection is not None:
                try:
                    await connection.close()
                except Exception:
                    LOG.exception("error closing NATS connection")

    await _flush_pending(scorer, baseline_path, pending_acks)
    LOG.info("UEBA worker stopped")


async def _consume(
    subscription: Any,
    jetstream: Any,
    scorer: BaselineScorer,
    baseline_path: Path,
    pending_acks: list[Any],
    stopping: asyncio.Event,
    batch_size: int,
    checkpoint_size: int,
) -> None:
    while not stopping.is_set():
        try:
            messages = await subscription.fetch(batch_size, timeout=1)
        except NatsTimeoutError:
            await _flush_pending(scorer, baseline_path, pending_acks)
            continue

        for message in messages:
            try:
                event = json.loads(message.data)
                if not isinstance(event, dict) or not _valid_event(event):
                    LOG.warning("terminating malformed event on %s", message.subject)
                    await message.term()
                    continue
                result = scorer.observe_event(event)
                if result.anomalous:
                    alert = _alert_envelope(event, result, scorer.anomaly_threshold)
                    event_id = event["event_id"]
                    await jetstream.publish(
                        ALERT_SUBJECT,
                        json.dumps(alert, separators=(",", ":")).encode("utf-8"),
                        headers={"Nats-Msg-Id": f"ueba-{event_id}"},
                    )
                    LOG.warning(
                        "UEBA anomaly score %.2f for event %s on host %s",
                        result.score,
                        event_id,
                        event["host"]["host_id"],
                    )
                pending_acks.append(message)
            except (json.JSONDecodeError, UnicodeDecodeError):
                LOG.warning("terminating event with invalid JSON on %s", message.subject)
                await message.term()
            except Exception:
                LOG.exception("UEBA processing failed; event will be retried")
                await message.nak(delay=5)
            if len(pending_acks) >= checkpoint_size:
                await _flush_pending(scorer, baseline_path, pending_acks)


async def _flush_pending(
    scorer: BaselineScorer,
    baseline_path: Path,
    pending_acks: list[Any],
) -> None:
    if not pending_acks:
        return
    await asyncio.to_thread(scorer.save, baseline_path)
    while pending_acks:
        message = pending_acks[0]
        await message.ack_sync(timeout=5)
        pending_acks.pop(0)


def _load_scorer(baseline_path: Path) -> tuple[BaselineScorer, bool]:
    if baseline_path.exists():
        scorer = BaselineScorer.load(baseline_path)
        LOG.info("loaded UEBA baseline with %d observations", scorer.baseline_size())
        return scorer, True

    scorer = BaselineScorer(
        warmup_observations=_positive_int_env("SF_UEBA_WARMUP_OBSERVATIONS", 25),
        anomaly_threshold=float(os.getenv("SF_UEBA_ANOMALY_THRESHOLD", "65")),
        max_entity_scopes=_positive_int_env("SF_UEBA_MAX_ENTITY_SCOPES", 10_000),
    )
    seed_file = os.getenv("SF_UEBA_BASELINE_SEED")
    if seed_file:
        learned = 0
        with Path(seed_file).open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid baseline seed JSON at line {line_number}") from error
                if not isinstance(event, dict) or not _valid_event(event):
                    raise ValueError(f"invalid event envelope at baseline seed line {line_number}")
                scorer.learn_event(event)
                learned += 1
        if learned == 0:
            raise ValueError("baseline seed file contains no events")
        scorer.save(baseline_path)
        LOG.info("seeded UEBA baseline with %d trusted events", learned)
        return scorer, True
    else:
        LOG.warning(
            "no baseline or SF_UEBA_BASELINE_SEED found; starting at new stream events and learning during live warm-up"
        )
    return scorer, False


def _alert_envelope(
    event: Mapping[str, Any],
    result: ScoreResult,
    threshold: float,
) -> dict[str, Any]:
    assert result.score is not None
    severity = _severity(result.score)
    lead_feature = result.explanations[0].feature if result.explanations else "behavior"
    return {
        "event_id": event["event_id"],
        "event": event,
        "detection_type": "ueba",
        "anomaly_score": result.score,
        "threshold": threshold,
        "ready": result.ready,
        "observations_remaining": result.observations_remaining,
        "matches": [
            {
                "rule_id": "UEBA-CATEGORICAL-BASELINE",
                "title": f"Unusual {lead_feature} behavior",
                "level": severity,
                "anomaly_score": result.score,
                "evidence": [
                    {
                        "scope": item.scope,
                        "feature": item.feature,
                        "value": item.value,
                        "score": item.score,
                        "observed_count": item.observed_count,
                        "observation_count": item.observation_count,
                    }
                    for item in result.explanations
                ],
            }
        ],
    }


def _severity(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 65:
        return "medium"
    return "low"


def _valid_event(event: Mapping[str, Any]) -> bool:
    host = event.get("host")
    return (
        isinstance(event.get("event_id"), str)
        and bool(event["event_id"])
        and isinstance(host, Mapping)
        and isinstance(host.get("host_id"), str)
        and bool(host["host_id"])
    )


def _positive_int_env(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def main() -> None:
    logging.basicConfig(
        level=os.getenv("SF_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
