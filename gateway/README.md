# Ingestion gateway and local alert dashboard

This is the first Go gateway slice for M1. It exposes:

- `GET /healthz` for process health.
- `POST /v1/events` for validating one JSON event shaped like the documented event example.
- `GET /` for the local React analyst dashboard.
- `GET /v1/alerts` for recent alert summaries (loopback requests only; `limit` is capped at 100).
- `GET /v1/alerts/{eventID}` for stored alert and event evidence (loopback requests only).

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

Open `http://127.0.0.1:8080/` on the gateway machine for the analyst dashboard.
It shows recent alert metrics, severity and activity summaries, and a searchable,
filterable queue. Open a row to inspect stored event and rule evidence, update
triage state, and add notes. Triage state and notes are stored in that browser's
local storage only; they are not shared or persisted by the server. Evidence and
summary endpoints are loopback-only because user authentication is not yet
implemented.

The prebuilt React bundle is embedded in the Go binary. To rebuild it after
editing the UI, use Node.js 20.19+ and run:

```sh
cd ../dashboard-ui
npm ci
npm run build
```

Run the event-store consumer in a second terminal:

```sh
go run ./cmd/event-store
```

It creates the `sentinelforge.events` and `sentinelforge.alerts` ClickHouse
tables and consumes both durable JetStream streams. The `EVENT_STORE` and
`ALERT_STORE` consumers acknowledge each message only after ClickHouse accepts
the insert; failed inserts are retried after five seconds. Detection alerts
retain searchable rule IDs and levels plus the full alert and event evidence
JSON. Configure `SF_NATS_URL`, `SF_CLICKHOUSE_URL`, `SF_CLICKHOUSE_USER`, and
`SF_CLICKHOUSE_PASSWORD` to use non-default endpoints or credentials.

This JSON route is a development scaffold. The versioned Protobuf contract in
`../proto/events/v1/event.proto` remains authoritative for the planned gRPC
transport and agent authentication.
