# SentinelForge Correlation

This package adds the enrichment, ATT&CK mapping, and attack-chain correlation components for SentinelForge.

It provides:
- ATT&CK technique lookup and mapping helpers
- alert enrichment and risk scoring
- alert clustering and incident generation
- live JetStream consumers for enriched alerts and incident snapshots
- CISA KEV, FIRST EPSS, and configurable JSON IOC feed loaders

## Quick usage

```python
from sentinelforge_correlation import ATTACKMapper, EnrichmentEngine, CorrelationEngine

mapper = ATTACKMapper()
techniques = mapper.map_alert({"techniques": ["T1059.001", "T1078"]})

alert = {"alert_id": "A-1", "title": "PowerShell execution", "severity": "high", "source_ip": "1.2.3.4"}
scored = EnrichmentEngine().enrich(alert)

incidents = CorrelationEngine().correlate([alert])
```

## Live M6 worker

Install the package and start `sentinelforge-m6-worker`, or use the
`enrichment-correlation` service in `deploy/docker-compose.yml`. It consumes
`SENTINELFORGE_ALERTS`, enriches detection envelopes, publishes them to
`SENTINELFORGE_ENRICHED`, and publishes rolling correlated incident snapshots
to `SENTINELFORGE_INCIDENTS`. Both output streams are created by the worker.

The worker loads CISA KEV at startup and refreshes configured threat feeds
every six hours by default. FIRST EPSS scores are fetched on demand for CVEs
present on alerts. IOC feeds must return JSON as either an indicator-to-label
object or a list of records containing `indicator`/`value` and an optional
`description`/`threat` field.

Configuration:

- `SF_NATS_URL`: JetStream server URL.
- `SF_KEV_ENABLED`, `SF_KEV_URL`: enable or override the CISA KEV JSON source.
- `SF_EPSS_URL`: override the FIRST EPSS lookup endpoint.
- `SF_THREAT_INTEL_URLS`: comma-separated JSON IOC feed URLs.
- `SF_ASSET_CRITICALITY_JSON`: optional JSON map of asset labels to
  `low`/`medium`/`high`/`critical` criticality values.
- `SF_FEED_REFRESH_SECONDS`, `SF_FEED_TIMEOUT_SECONDS`: feed refresh and
  request timeout controls.
- `SF_CORRELATION_WINDOW_SECONDS`, `SF_CORRELATION_MAX_HISTORY`: rolling
  correlation window and in-memory history bound.

External feed failures are logged and do not prevent alert processing. Feed
data and correlation history are held in memory; incident snapshots are
published to JetStream, but the worker does not yet upsert an incident database.
