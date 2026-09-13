#!/usr/bin/env python3
"""Print the per-metric reasons the forecaster declined, from the audit log.

The user-facing message now names one reason, but a run that already
happened only recorded them. The enrichment provider writes every skipped
metric's InsufficientHistory text into the audit event's parameters, so the
answer to "why was there no forecast evidence" is already on disk.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=Path("var/audit.jsonl"))
    parser.add_argument(
        "--alert-id", default=None, help="Only this alert, if given."
    )
    args = parser.parse_args()

    if not args.audit.is_file():
        raise SystemExit(f"{args.audit} does not exist")

    found = 0
    for line in args.audit.open("r", encoding="utf-8"):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        parameters = record.get("parameters") or {}
        if parameters.get("kind") != "forecast":
            continue
        if args.alert_id and record.get("alert_id") != args.alert_id:
            continue
        skipped = parameters.get("skipped")
        reason = parameters.get("reason")
        if not skipped and not reason:
            continue
        found += 1
        print(f"\n{record.get('timestamp', '?')}  {record.get('alert_id', '?')}")
        print(f"  entity           {parameters.get('entity')}")
        print(f"  bucket_seconds   {parameters.get('bucket_seconds')}")
        print(f"  history_buckets  {parameters.get('history_buckets')}")
        print(f"  horizon_buckets  {parameters.get('horizon_buckets')}")
        if reason:
            print(f"  reason           {reason}")
        for entry in skipped or []:
            print(f"  declined         {entry}")

    if not found:
        print(
            f"No forecast audit records in {args.audit}. Enrichment only "
            "writes them when NETWORK_DORK_FORECAST_ADAPTER=enrichment is set."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
