# SentinelForge Assistant

M7 adds a small read-only investigation service. It retrieves bounded recent
event and alert records through the gateway's GET APIs, sends that evidence to
an OpenAI-compatible chat completion endpoint, and returns citations keyed by
stored event IDs. Telemetry is marked as untrusted in the model instructions.

## Run

Install with `pip install -e assistant`, then start:

```powershell
sentinelforge-assistant
```

The default listener is `127.0.0.1:8090`. POST a JSON body to
`/v1/investigate`:

```json
{
  "question": "What happened on host-07?",
  "host_id": "host-07",
  "limit": 50
}
```

For an alert-focused explanation, POST `{"alert_id":"<event-id>"}` to
`/v1/explain-alert`. This retrieves the matching stored alert and event record,
then asks the model to describe its rule or anomaly evidence and distinguish
observations from interpretation.

For an incident timeline, POST `{"incident_id":"INC-..."}` to
`/v1/investigate-incident`. The assistant uses stored incident snapshots and
their linked source alerts. The dashboard's incident cards and detection rows
provide one-click investigation and explanation actions; its chat panel posts
through the gateway's same-origin assistant routes.

## Configuration

- `SF_ASSISTANT_ADDR`: listener address, default `127.0.0.1:8090`.
- `SF_GATEWAY_URL`: gateway base URL, default `http://127.0.0.1:8080`.
- `SF_ASSISTANT_MODEL_URL`: OpenAI-compatible `/v1/chat/completions` URL;
  defaults to local Ollama at `http://127.0.0.1:11434/v1/chat/completions`.
- `SF_ASSISTANT_MODEL`: model name, default `qwen2.5:7b`.
- `SF_ASSISTANT_API_KEY`: optional bearer token for hosted model endpoints.
- `SF_ASSISTANT_BEARER_TOKEN`: require this bearer token on investigation
  requests; mandatory when binding outside loopback.
- `SF_ASSISTANT_AUDIT_PATH`: JSONL audit path, default
  `data/assistant-audit.jsonl`.

The assistant exposes no write tools or response actions. It can retrieve only
the gateway's bounded recent event, alert, and incident lists. Returned citations
are checked against the retrieved event IDs; unsupported citation IDs are
reported separately. If no matching evidence is found, the model is not called.
