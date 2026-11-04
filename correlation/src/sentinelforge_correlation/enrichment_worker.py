"""Command-line entrypoint for alert enrichment."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .enrichment import EnrichmentEngine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich SentinelForge alerts with IOCs, KEV and asset context.")
    parser.add_argument("--json", type=str, help="A JSON string to enrich. Defaults to stdin.")
    args = parser.parse_args(argv)

    payload = args.json
    if payload is None:
        import sys

        payload = sys.stdin.read().strip()

    if not payload:
        return 0

    engine = EnrichmentEngine()
    alert = json.loads(payload)
    item = engine.enrich(alert)
    print(json.dumps(item.as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
