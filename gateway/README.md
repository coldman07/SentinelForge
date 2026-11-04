# Ingestion gateway and telemetry dashboard

This is the first Go gateway slice for M1. It exposes:

- `GET /healthz` for process health.
- `POST /v1/events` for validating one JSON event shaped like the documented event example.
- `GET /` for the local read-only telemetry dashboard.
- `GET /v1/events` for recent stored events (loopback only; limit capped at 100).
- `GET /v1/alerts` for recent Sigma detections and evidence (loopback only; limit capped at 100).
- `GET /v1/incidents` for persisted correlated incident snapshots (loopback only; limit capped at 100).
- `POST /v1/assistant/investigate`, `/v1/assistant/explain-alert`, and `/v1/assistant/investigate-incident` as same-origin proxies to the local read-only assistant.

Start the local event bus and event store from the repository root:

```sh
docker compose -f deploy/docker-compose.yml up -d nats clickhouse
```

Run the gateway with Go 1.22 or newer:

```sh
go run .
```

The listener defaults to `:8080`; set `SF_GATEWAY_ADDR` to change it. Requests
are limited to 1 MiB. The route returns `202 Accepted` only after JetStream
confirms the event in the durable `SENTINELFORGE_EVENTS` stream. Messages use
subjects `sentinelforge.events.v1.<category>`.

Open `http://127.0.0.1:8080/` on the gateway machine for the dashboard. It
shows recent event counts, category distribution, searchable and filterable
activity, and expandable raw event evidence. It refreshes every 15 seconds.
The event endpoint is restricted to loopback requests because user
authentication has not been implemented.

Run the event-store consumer in a second terminal:

```sh
go run ./cmd/event-store
```

It creates event, alert, and incident ClickHouse tables and consumes the
durable JetStream streams. The `EVENT_STORE`, `ALERT_STORE`, and `INCIDENT_STORE`
consumers acknowledge messages only after ClickHouse accepts
each insert; failed inserts are retried after five seconds. Alert rows keep
searchable rule IDs, titles and levels plus the complete alert and event
evidence. Incident rows keep the latest correlated snapshot and linked alerts.
Configure `SF_NATS_URL`, `SF_CLICKHOUSE_URL`, `SF_CLICKHOUSE_USER`,
and `SF_CLICKHOUSE_PASSWORD` to use non-default endpoints or credentials.

Start `sentinelforge-assistant` on the gateway machine for dashboard chat and
explanation actions. Set `SF_ASSISTANT_URL` on the gateway if it listens
somewhere other than `http://127.0.0.1:8090`.

This JSON route is a development scaffold. The versioned Protobuf contract in
`../proto/events/v1/event.proto` remains authoritative for the planned gRPC
transport and agent authentication.
