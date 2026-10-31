# Ingestion gateway skeleton

This is the first Go gateway slice for M1. It exposes:

- `GET /healthz` for process health.
- `POST /v1/events` for validating one JSON event shaped like the documented event example.

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

Run the event-store consumer in a second terminal:

```sh
go run ./cmd/event-store
```

It creates the `sentinelforge.events` ClickHouse table and consumes events from
JetStream. The durable `EVENT_STORE` consumer acknowledges each message only
after ClickHouse accepts the insert; failed inserts are retried after five
seconds. Configure `SF_NATS_URL`, `SF_CLICKHOUSE_URL`, `SF_CLICKHOUSE_USER`, and
`SF_CLICKHOUSE_PASSWORD` to use non-default endpoints or credentials.

This JSON route is a development scaffold. The versioned Protobuf contract in
`../proto/events/v1/event.proto` remains authoritative for the planned gRPC
transport and agent authentication.
