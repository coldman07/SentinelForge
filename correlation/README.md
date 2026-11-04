# SentinelForge Correlation

This package adds the enrichment, ATT&CK mapping, and attack-chain correlation components for SentinelForge.

It provides:
- ATT&CK technique lookup and mapping helpers
- alert enrichment and risk scoring
- alert clustering and incident generation

## Quick usage

```python
from sentinelforge_correlation import ATTACKMapper, EnrichmentEngine, CorrelationEngine

mapper = ATTACKMapper()
techniques = mapper.map_alert({"techniques": ["T1059.001", "T1078"]})

alert = {"alert_id": "A-1", "title": "PowerShell execution", "severity": "high", "source_ip": "1.2.3.4"}
scored = EnrichmentEngine().enrich(alert)

incidents = CorrelationEngine().correlate([alert])
```
