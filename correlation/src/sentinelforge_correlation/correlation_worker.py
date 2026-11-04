"""Command-line entrypoint for attack-chain correlation."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .correlation import CorrelationEngine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Correlate SentinelForge alerts into incidents.")
    parser.add_argument("--json", type=str, help="A JSON array of alerts to correlate. Defaults to stdin.")
    args = parser.parse_args(argv)

    payload = args.json
    if payload is None:
        import sys

        payload = sys.stdin.read().strip()

    if not payload:
        return 0

    engine = CorrelationEngine()
    alerts = json.loads(payload)
    incidents = engine.correlate(alerts)
    print(json.dumps([incident.as_dict() for incident in incidents], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
