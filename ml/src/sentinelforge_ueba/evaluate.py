"""CLI for offline evaluation with trusted baseline and labeled JSONL files."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from .evaluation import LabeledEvent, evaluate_labeled_events
from .scorer import BaselineScorer


def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from error
            if not isinstance(record, dict):
                raise ValueError(f"expected a JSON object at {path}:{line_number}")
            yield record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-events", type=Path, required=True)
    parser.add_argument("--labeled-events", type=Path, required=True)
    parser.add_argument("--warmup-observations", type=int, default=25)
    parser.add_argument("--threshold", type=float, default=65.0)
    args = parser.parse_args()

    scorer = BaselineScorer(
        warmup_observations=args.warmup_observations,
        anomaly_threshold=args.threshold,
    )
    baseline_count = 0
    for event in _read_jsonl(args.baseline_events):
        scorer.learn_event(event)
        baseline_count += 1

    def labeled_events() -> Iterator[LabeledEvent]:
        for record in _read_jsonl(args.labeled_events):
            event = record.get("event")
            label = record.get("anomalous")
            if not isinstance(event, Mapping) or not isinstance(label, bool):
                raise ValueError(
                    "labeled rows require an event object and boolean anomalous label"
                )
            yield LabeledEvent(event=event, anomalous=label)

    metrics = evaluate_labeled_events(
        scorer,
        labeled_events(),
        threshold=args.threshold,
    )
    print(
        json.dumps(
            {
                "baseline_events": baseline_count,
                "metrics": metrics.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
