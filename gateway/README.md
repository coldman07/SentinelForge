# Ingestion gateway and telemetry dashboard

This is the first Go gateway slice for M1. It exposes:

- `GET /healthz` for process health.
- `POST /v1/events` for validating one JSON event shaped like the documented event example.
- `GET /` for the local read-only telemetry dashboard.
- `GET /v1/events` for recent stored events (loopback only; limit capped at 100).
- `GET /v1/alerts` for recent Sigma detections and evidence (loopback only; limit capped at 100).
- `GET /v1/incidents` for persisted correlated incident snapshots (loopback only; limit capped at 100).
- `POST /v1/assistant/investigate`, `/v1/assistant/explain-alert`, and `/v1/assistant/investigate-incident` as same-origin proxies to the local read-only assistant.
- `/v1/rules/...`, `/v1/response-requests...`, and `/v1/audit...` for the M8 candidate lifecycle, response approval queue, and audit chain (loopback only; writes require role bearer tokens).

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

Open `http://127.0.0.1:8080/` on the gateway machine for the React analyst
dashboard. It shows event and detection summaries, filters, matched rule and
event evidence, correlated incidents, and evidence-cited alert/incident
investigations. Data refreshes every 15 seconds. The Vite production bundle is
embedded in the Go binary; rebuild it after UI changes:

```sh
cd dashboard-ui
npm ci
npm run build
```

The build writes static assets to `gateway/internal/dashboard/dist`, which are
served by the gateway alongside the API.
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

M8 rule lifecycle endpoints:

- `POST /v1/rules/candidates` with `{"rule_yaml":"..."}` parses the rule
  through the Rust evaluator and stores a validated candidate.
- `POST /v1/rules/candidates/{candidateID}/replay` with `positive_events` and
  `negative_events` runs the same Sigma evaluator. Approval requires at least
  one positive match and zero benign matches (1-500 events per set).
- `POST /v1/rules/candidates/{candidateID}/approve` requires an approver/admin
  token different from the candidate author and an HMAC signing key.
- `GET /v1/rules/{ruleID}/versions` lists immutable versions;
  `POST /v1/rules/{ruleID}/rollback` with a version number records a new signed
  version based on that earlier version.
- `POST /v1/response-requests` submits an action, target, and justification.
  OPA allows `tag_host`/`collect_artifacts` with a valid justification;
  `network_isolate_host`, `kill_process`, and `disable_account` require a
  different approver. These records do not execute response actions.
- `GET /v1/audit` lists the hash-chained audit log and
  `GET /v1/audit/verify` checks its chain.

All control-plane routes are loopback-only. Reads need no role token; writes
require a bearer token from `SF_CONTROL_TOKENS_JSON`, whose entries map tokens
to `{id, role}` principals (`analyst`, `approver`, or `admin`). Rule validation
and replay require the built Rust binary configured by `SF_DETECTION_BIN`.
OPA is fail-closed: if it is unavailable, response requests and approvals are
not accepted. Approved versions are stored and signed, but this slice does not
hot-reload or distribute them to running detection workers.

For M8, start OPA with `docker compose -f deploy/docker-compose.yml up -d opa`
and build the validator executable with
`cargo build --release --manifest-path detection/Cargo.toml`. Set
`SF_DETECTION_BIN` to that executable, `SF_RULE_SIGNING_KEY` to a private key
of at least 32 bytes, and `SF_CONTROL_TOKENS_JSON` to a JSON map such as
`{"analyst-secret":{"id":"analyst-1","role":"analyst"},"approver-secret":{"id":"lead-1","role":"approver"}}`.
Never commit these values. M8 rule approvals create signed immutable versions
and rollback records; distributing approved rules to running detection workers
and executing response actions remain outside this slice.

This JSON route is a development scaffold. The versioned Protobuf contract in
`../proto/events/v1/event.proto` remains authoritative for the planned gRPC
transport and agent authentication.

## M9 transport and update hardening

Set `SF_MTLS_REQUIRED=true` to require TLS 1.3 and verified client certificates
on the gateway listener and to require client certificates for NATS connections.
The gateway needs `SF_GATEWAY_CERT_FILE`, `SF_GATEWAY_KEY_FILE`, and
`SF_CLIENT_CA_FILE`. Go services use `SF_NATS_CA_FILE`, `SF_NATS_CERT_FILE`,
and `SF_NATS_KEY_FILE`. The Windows sensor uses `SF_GATEWAY_CA_FILE`,
`SF_GATEWAY_CERT_FILE`, and `SF_GATEWAY_KEY_FILE`, and requires an `https://`
`SF_GATEWAY_URL`. The M8 local defaults remain available when the switch is
false. Compose switches NATS to its client-certificate-required listener when
`SF_MTLS_REQUIRED=true`; provide the matching files under `deploy/certs/`.

For an isolated lab CA and certificates, run
`SF_GATEWAY_DNS_NAME=<gateway-dns-name> sh deploy/generate-dev-certs.sh` from
the repository root. The script writes private keys to the ignored
`deploy/certs/` directory. It creates distinct NATS client identities for the
gateway, event store, detector, UEBA worker, and correlation worker. Point each
process at its own certificate. The gateway certificate includes the DNS name
supplied to the script; use that exact hostname in the sensor URL. These are
development credentials, not a production certificate lifecycle.

The Rust detection worker and Python UEBA/correlation workers accept the same
NATS CA/client identity paths when mTLS is enabled. Compose mounts certificates
read-only; issue a distinct certificate/key for each service and keep private
keys out of source control. This configuration secures the listed links; it
does not configure TLS for ClickHouse or OPA.

`go run ./cmd/update-verify keygen update-signing.key update-verification.key`
creates an Ed25519 key pair (protect the private key). Use
`go run ./cmd/update-verify sign <artifact> <version> <private-key> <manifest>`
to create a signed digest manifest and `... verify <artifact> <public-key>
<manifest>` to verify it. Verification does not install or execute updates.
