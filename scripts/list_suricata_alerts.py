#!/usr/bin/env python3
"""List the alert identifiers in a Suricata eve.json, as this project sees them.

`trace --alert-id` needs the normalized identifier, which is built from the
flow id, the signature id and the line number rather than appearing in
eve.json directly. Deriving it by hand from a file with a quarter of a
million events is not reasonable, so this prints them.

Signature counts come first, because on ordinary traffic most alerts are
protocol anomalies rather than anything worth investigating, and picking a
good one to demonstrate matters more than picking the first one.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from network_dork.adapters.identity import normalize_alert_id  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--eve",
        type=Path,
        default=Path("var/real/eve.json"),
        help="Suricata eve.json to read.",
    )
    parser.add_argument(
        "--source-name",
        default="suricata-eve",
        help="Must match the adapter's source_name, or ids will not match.",
    )
    parser.add_argument(
        "--signature",
        default=None,
        help="Only list alerts whose signature contains this text.",
    )
    args = parser.parse_args()

    if not args.eve.is_file():
        raise SystemExit(f"{args.eve} does not exist")

    found: list[tuple[str, str, str]] = []
    signatures: Counter[str] = Counter()
    with args.eve.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or event.get("event_type") != "alert":
                continue
            block = event.get("alert")
            if not isinstance(block, dict):
                continue
            signature = str(block.get("signature") or "Suricata alert")
            signatures[signature] += 1
            if args.signature and args.signature.lower() not in signature.lower():
                continue
            alert_id = normalize_alert_id(
                args.source_name,
                f"{event.get('flow_id', 'no-flow')}:"
                f"{block.get('signature_id', 'no-sid')}:{line_number}",
            )
            found.append((alert_id, signature, str(event.get("timestamp", ""))))

    if not signatures:
        raise SystemExit(
            f"No alert events in {args.eve}. Suricata needs rules: run "
            "`sudo suricata-update` and process the capture again."
        )

    print(f"{sum(signatures.values())} alert(s) by signature:\n")
    for signature, count in signatures.most_common():
        print(f"  {count:>4}  {signature}")

    print(f"\n{len(found)} alert id(s) for --alert-id:\n")
    for alert_id, signature, timestamp in found:
        print(f"  {alert_id}")
        print(f"      {signature}  ({timestamp})")

    if found:
        print(
            "\nPick one and pass it as --alert-id. Protocol-anomaly "
            "signatures (SURICATA STREAM, decoder events) make a duller "
            "demonstration than a policy or malware signature."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
