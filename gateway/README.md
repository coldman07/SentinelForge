# Ingestion gateway skeleton

This is the first Go gateway slice for M1. It exposes:

- `GET /healthz` for process health.
- `POST /v1/events` for validating one JSON event shaped like the documented event example.

Start the local event bus from the repository root:

```sh
docker compose -f deploy/docker-compose.yml up -d nats
```

Run the gateway with Go 1.22 or newer:

```sh
go run .
```

The listener defaults to `:8080`; set `SF_GATEWAY_ADDR` to change it. Requests
are limited to 1 MiB. The route returns `202 Accepted` only when a configured
`Publisher` accepts the event. Until the event-bus slice is connected, ingestion
publishes to the durable `SENTINELFORGE_EVENTS` stream. Messages use subjects
`sentinelforge.events.v1.<category>` and are acknowledged only after JetStream
confirms storage.

This JSON route is a development scaffold. The versioned Protobuf contract in
`../proto/events/v1/event.proto` remains authoritative for the planned gRPC
transport and agent authentication.
