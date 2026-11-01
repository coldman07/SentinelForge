# SentinelForge UEBA primitives

This package provides the initial M5 UEBA implementation: a Python library
that extracts categorical behavior features from the event envelope and
scores them against per-host, per-user and per-image baselines held in memory
and optionally persisted as JSON. The JetStream worker uses `nats-py`.

It currently models process images and parent-child pairs, per-image launch
hours and parent images, per-image file actions/extensions and network
destinations/ports, authentication method/outcome/source, and UTC event hour.
Each score includes its highest-surprise feature values and the number of times
those values appeared in the baseline. User and per-process profiles are
capped by `max_entity_scopes` to limit memory use.

## Use

Install the local package from this directory:

```sh
python -m pip install -e .
```

Then use it from a consumer process:

```python
from sentinelforge_ueba import BaselineScorer

scorer = BaselineScorer(warmup_observations=25)
for trusted_event in known_good_events:
    scorer.learn_event(trusted_event)
scorer.save("trusted-baseline.json")

scorer = BaselineScorer.load("trusted-baseline.json")

result = scorer.observe_event(live_event)
if result.anomalous:
    print(result.to_dict())
```

For offline evaluation, train the scorer on a trusted event window, then score
labeled samples without mutating the baseline:

```python
from sentinelforge_ueba import LabeledEvent, evaluate_labeled_events

metrics = evaluate_labeled_events(
    scorer,
    [LabeledEvent(event=event, anomalous=label) for event, label in labeled_rows],
)
print(metrics.to_dict())
```

Metrics include precision, recall, false-positive rate, accuracy, and
readiness coverage. Unready samples count as negative predictions and are
reported separately, so a warm-up-heavy run cannot appear fully evaluated.
The synthetic fixtures in `../datasets/ueba/` can be evaluated with
`sentinelforge-ueba-evaluate`; they are examples only, not representative
endpoint telemetry.

Feed `learn_event` only known-good baseline data. `observe_event` scores before
updating and does not learn a high-scoring event after host warm-up, which
reduces baseline poisoning. Save trusted baselines with `save(path)` and
restore them with `BaselineScorer.load(path)`. The JSON file contains observed
process paths, usernames and network destinations, so protect it with suitable
filesystem permissions and retention. File and network events include an
optional process reference when the sensor resolves the event PID to an image;
events without a resolved process are scored only at host/user scope. The worker
creates a durable consumer on
`SENTINELFORGE_EVENTS`, checkpoints baselines before acknowledging messages,
and publishes anomaly scores with feature evidence to
`SENTINELFORGE_ALERTS`. If no baseline or seed file exists, it consumes new
events only and learns during warm-up; seed it with trusted JSONL events for
production use. The demo data is synthetic, and this remains an early-stage
baseline service rather than a trained classifier or production alerting
service.

## JetStream worker

Run `sentinelforge-ueba` after installing the package. The Compose profile in
`deploy/docker-compose.yml` starts the worker and mounts `/data` for its
baseline file. Main settings are `SF_NATS_URL`, `SF_UEBA_BASELINE_PATH`,
`SF_UEBA_BASELINE_SEED`, `SF_UEBA_WARMUP_OBSERVATIONS`,
`SF_UEBA_ANOMALY_THRESHOLD` and `SF_UEBA_DURABLE_NAME`. The seed file is
newline-delimited full event objects and is read only when no saved baseline
exists. Back up the baseline volume together with NATS consumer state.
