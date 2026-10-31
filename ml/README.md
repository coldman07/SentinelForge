# SentinelForge UEBA primitives

This package is the first M5 implementation slice: a dependency-free Python
library that extracts categorical behavior features from the event envelope
and scores them against per-host and per-user baselines held in memory and
optionally persisted as JSON.

It currently models process images and parent-child pairs, file actions and
extensions, network destinations and ports, authentication method/outcome/
source, and UTC event hour. Each score includes its highest-surprise feature
values and the number of times those values appeared in the baseline.

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

Feed `learn_event` only known-good baseline data. `observe_event` scores before
updating and does not learn a high-scoring event after host warm-up, which
reduces baseline poisoning. Save trusted baselines with `save(path)` and
restore them with `BaselineScorer.load(path)`. The JSON file contains observed
process paths, usernames and network destinations, so protect it with suitable
filesystem permissions and retention. JetStream consumption, per-process
profiles, temporal windows, model evaluation and alert publishing remain later
M5 integration work. This scorer is an explainable baseline primitive, not a
trained classifier or a production alerting service.
