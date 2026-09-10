#!/usr/bin/env python3
"""Build a small sample network you can point the engine at.

The shipped fixtures are deliberately thin: they exercise the code without
enough history to forecast, so enrichment correctly refuses to run on them.
That is right for tests and useless for learning what the engine does.

This writes a realistic environment instead -- twenty days of Zeek-shaped
connection logs for several hosts, plus alerts on three of them -- so you can
watch a full investigation including forecast evidence.

    python scripts/make_sample_network.py --destination var/sample
    NETWORK_DORK_ALERTS_PATH=var/sample/alerts.jsonl \\
    NETWORK_DORK_ZEEK_DIRECTORY=var/sample/zeek \\
    NETWORK_DORK_FORECAST_ADAPTER=enrichment \\
      python -m network_dork trace --alert-id sample-beacon --fake

One host beacons, one exfiltrates, one is entirely ordinary. Change the
numbers below and re-run to see how the engine's answers move: that loop is
the point of this script.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import random

BUCKET = 300
DAY = 288
SEED = 4711


def diurnal(index: int) -> float:
    """Busy in working hours, quiet overnight."""
    hour = ((index % DAY) * BUCKET) / 3600
    return 0.1 + 0.9 * math.sin(math.pi * min(max(hour - 6, 0), 14) / 14) ** 2


def write_network(destination: Path, days: int, now: datetime) -> dict:
    rng = random.Random(SEED)
    zeek = destination / "zeek"
    zeek.mkdir(parents=True, exist_ok=True)
    total = days * DAY
    start = now - timedelta(seconds=BUCKET * total)

    # (entity, base rate, bytes per connection, behaviour in the last 6 hours)
    hosts = [
        ("10.50.0.11", 6.0, 4200.0, "normal"),
        ("10.50.0.12", 9.0, 3800.0, "normal"),
        ("10.50.0.21", 5.0, 4000.0, "beacon"),
        ("10.50.0.22", 7.0, 4500.0, "exfil"),
    ]
    anomaly_from = total - 72  # last six hours

    conns: list[dict] = []
    dns_rows: list[dict] = []
    for entity, base, per_conn, behaviour in hosts:
        for index in range(total):
            moment = start + timedelta(seconds=BUCKET * index)
            shape = diurnal(index)
            count = max(0, base * shape * (1 + rng.gauss(0, 0.3)))
            payload = per_conn * (1 + rng.gauss(0, 0.3))

            if index >= anomaly_from:
                if behaviour == "beacon":
                    # Fixed interval, indifferent to the working day. Volume
                    # barely moves; the rhythm is what changes.
                    count = base * 2.4 * (1 + rng.gauss(0, 0.04))
                elif behaviour == "exfil":
                    payload *= 30
                    count *= 2.0

            for offset in range(int(count)):
                conns.append({
                    "ts": (moment + timedelta(seconds=offset * 3)).isoformat(),
                    "uid": f"C{rng.getrandbits(48):012x}",
                    "id.orig_h": entity,
                    "id.resp_h": (
                        "198.51.100.7"
                        if behaviour != "normal" and index >= anomaly_from
                        else f"203.0.113.{rng.randint(1, 40)}"
                    ),
                    "id.orig_p": rng.randint(32768, 60999),
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                    "orig_bytes": int(max(0, payload)),
                    "resp_bytes": int(max(0, payload * 0.2)),
                })
            if index % 12 == 0:
                dns_rows.append({
                    "ts": moment.isoformat(),
                    "id.orig_h": entity,
                    "query": (
                        "updates.example.test"
                        if behaviour == "normal" or index < anomaly_from
                        else "cdn-sync.example.test"
                    ),
                    "qtype_name": "A",
                    "rcode_name": "NOERROR",
                })

    conns.sort(key=lambda row: row["ts"])
    with (zeek / "conn.log").open("w", encoding="utf-8") as stream:
        for row in conns:
            stream.write(json.dumps(row) + "\n")
    with (zeek / "dns.log").open("w", encoding="utf-8") as stream:
        for row in sorted(dns_rows, key=lambda row: row["ts"]):
            stream.write(json.dumps(row) + "\n")
    (zeek / "auth.log").write_text("", encoding="utf-8")

    # Three alerts, as a sensor would already have raised them.
    alerts = [
        {
            "source": "sample-sensor",
            "alert_id": "sample-beacon",
            "timestamp": now.isoformat(),
            "title": "Repeated outbound HTTPS to a single destination",
            "description": "Sensor observed persistent low-volume callbacks.",
            "src_ip": "10.50.0.21",
            "dst_ip": "198.51.100.7",
            "host": "workstation-21.sample",
            "domains": ["cdn-sync.example.test"],
            "original": {"sensor_rule": "OUTBOUND_PERSISTENT"},
        },
        {
            "source": "sample-sensor",
            "alert_id": "sample-exfil",
            "timestamp": now.isoformat(),
            "title": "Large sustained outbound transfer",
            "description": "Sensor observed unusual outbound volume.",
            "src_ip": "10.50.0.22",
            "dst_ip": "198.51.100.7",
            "host": "workstation-22.sample",
            "domains": ["cdn-sync.example.test"],
            "original": {"sensor_rule": "OUTBOUND_VOLUME"},
        },
        {
            "source": "sample-sensor",
            "alert_id": "sample-quiet",
            "timestamp": now.isoformat(),
            "title": "Policy match on outbound HTTPS",
            "description": "Sensor matched a broad policy rule.",
            "src_ip": "10.50.0.11",
            "dst_ip": "203.0.113.9",
            "host": "workstation-11.sample",
            "domains": ["updates.example.test"],
            "original": {"sensor_rule": "POLICY_BROAD"},
        },
    ]
    with (destination / "alerts.jsonl").open("w", encoding="utf-8") as stream:
        for alert in alerts:
            stream.write(json.dumps(alert) + "\n")

    return {"connections": len(conns), "alerts": len(alerts)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path("var/sample"))
    parser.add_argument(
        "--days", type=int, default=20, help="History to generate."
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    counts = write_network(args.destination, args.days, now)

    # Three exports retyped in every new terminal is the kind of friction
    # that stops people from re-running the loop. Write them once.
    env_path = Path(args.destination) / "env.sh"
    env_path.write_text(
        "# Point network-dork at this sample network:\n"
        "#   source " + str(env_path) + "\n"
        f"export NETWORK_DORK_ALERTS_PATH={args.destination}/alerts.jsonl\n"
        f"export NETWORK_DORK_ZEEK_DIRECTORY={args.destination}/zeek\n"
        "export NETWORK_DORK_FORECAST_ADAPTER=enrichment\n",
        encoding="utf-8",
    )

    print(f"Wrote {counts['connections']:,} connections over {args.days} days")
    print(f"      {counts['alerts']} alerts to {args.destination}/alerts.jsonl")
    print()
    print("Point the engine at it:")
    print()
    print(f"  source {env_path}")
    print("  python -m network_dork config --changed   # confirm it took")
    print()
    print("Then try each of these and compare what comes back:")
    print()
    print("  python -m network_dork readiness")
    print("  python -m network_dork trace --alert-id sample-beacon --fake")
    print("  python -m network_dork trace --alert-id sample-exfil  --fake")
    print("  python -m network_dork trace --alert-id sample-quiet  --fake")
    print()
    print("sample-quiet should produce no forecast evidence. If it does,")
    print("the thresholds are too low for this data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
