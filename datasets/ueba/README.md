# UEBA demo data

`known_good.jsonl` and `labeled_scenarios.jsonl` are synthetic examples for
the offline evaluator. They use one fictitious Windows host and contain no
observed or customer telemetry. The five baseline process events are only
enough to demonstrate a scorer configured with `warmup_observations=5`; they
are not representative of an enterprise baseline or suitable as production
training data.

From `ml/`, install the package and evaluate the sample:

```sh
python -m pip install -e .
sentinelforge-ueba-evaluate \
  --baseline-events ../datasets/ueba/known_good.jsonl \
  --labeled-events ../datasets/ueba/labeled_scenarios.jsonl \
  --warmup-observations 5
```
