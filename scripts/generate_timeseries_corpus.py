#!/usr/bin/env python3
"""Generate the labelled evaluation corpus.

Thirty days of five-minute buckets for nine synthetic hosts. Deterministic:
the same seed always produces the same corpus, so an evaluation result is
reproducible and a regression in scoring is visible as a changed number.

The corpus exists to measure false positives as much as detections. Three
hosts carry genuinely malicious windows; three carry *benign* windows that
look exactly as unusual -- a weekly backup, a monthly patch cycle, a newly
onboarded host. A forecaster that flags the benign three is not usable in a
SOC no matter how well it finds the malicious three, and no corpus made only
of attacks would ever show that.

Regenerate with:
    python scripts/generate_timeseries_corpus.py
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import random

SEED = 20260115
START = datetime(2025, 1, 1, tzinfo=timezone.utc)
BUCKET_SECONDS = 300
DAY_BUCKETS = 86400 // BUCKET_SECONDS  # 288
DAYS = 30
TOTAL = DAYS * DAY_BUCKETS
METRICS = ("conn_count", "bytes_out", "distinct_destinations")


@dataclass
class Window:
    """A labelled span. ``malicious`` drives scoring; the rest is context."""

    day: int
    start_hour: float
    hours: float
    category: str
    malicious: bool
    conn_multiplier: float = 1.0
    bytes_multiplier: float = 1.0
    destinations: int | None = None


@dataclass
class Host:
    entity: str
    profile: str
    note: str
    base_conns: float = 6.0
    bytes_per_conn: float = 4200.0
    base_destinations: float = 4.0
    weekend_factor: float = 0.35
    noise: float = 0.25
    active_from_day: int = 0
    windows: list[Window] = field(default_factory=list)


HOSTS = [
    Host(
        entity="10.10.0.11",
        profile="workstation-quiet",
        note="Ordinary weekday workstation. No events; measures false alarms.",
        base_conns=5.0,
        noise=0.18,
    ),
    Host(
        entity="10.10.0.12",
        profile="workstation-noisy",
        note="Same shape, much higher variance. Measures false alarms under noise.",
        base_conns=9.0,
        noise=0.65,
    ),
    Host(
        entity="10.10.0.13",
        profile="server-steady",
        note="Flat around the clock. No events.",
        base_conns=14.0,
        weekend_factor=0.95,
        noise=0.12,
    ),
    Host(
        entity="10.10.0.21",
        profile="backup-host",
        note="Benign weekly backup window. Looks like exfiltration.",
        base_conns=6.0,
        windows=[
            Window(
                day=day,
                start_hour=1.0,
                hours=3.0,
                category="scheduled_backup",
                malicious=False,
                conn_multiplier=3.5,
                bytes_multiplier=28.0,
            )
            # Sundays within the corpus.
            for day in (4, 11, 18, 25)
        ],
    ),
    Host(
        entity="10.10.0.22",
        profile="patch-host",
        note="Benign monthly patch cycle. Looks like a burst of new contacts.",
        base_conns=7.0,
        windows=[
            Window(
                day=9,
                start_hour=2.0,
                hours=4.0,
                category="patch_cycle",
                malicious=False,
                conn_multiplier=6.0,
                bytes_multiplier=9.0,
                destinations=22,
            )
        ],
    ),
    Host(
        entity="10.10.0.23",
        profile="onboarded-host",
        note="Benign: no traffic until day 20, then normal. Tests cold start.",
        base_conns=6.0,
        active_from_day=20,
    ),
    Host(
        entity="10.10.0.31",
        profile="beacon-host",
        note="Malicious: low-rate periodic callbacks, small payloads.",
        base_conns=6.0,
        windows=[
            Window(
                day=25,
                start_hour=9.0,
                hours=6.0,
                category="c2_beaconing",
                malicious=True,
                conn_multiplier=7.0,
                bytes_multiplier=1.4,
                destinations=2,
            )
        ],
    ),
    Host(
        entity="10.10.0.32",
        profile="exfil-host",
        note="Malicious: sustained outbound volume ramp.",
        base_conns=7.0,
        windows=[
            Window(
                day=27,
                start_hour=22.0,
                hours=4.0,
                category="data_exfiltration",
                malicious=True,
                conn_multiplier=2.2,
                bytes_multiplier=34.0,
            )
        ],
    ),
    Host(
        entity="10.10.0.33",
        profile="scan-host",
        note="Malicious: internal scanning, many short-lived destinations.",
        base_conns=8.0,
        windows=[
            Window(
                day=22,
                start_hour=14.0,
                hours=2.0,
                category="internal_scanning",
                malicious=True,
                conn_multiplier=9.0,
                bytes_multiplier=1.1,
                destinations=140,
            )
        ],
    ),
]


def diurnal(index: int, host: Host) -> float:
    """Working-hours shape with a weekend dip, in [0.08, 1.0]."""
    hour = ((index % DAY_BUCKETS) * BUCKET_SECONDS) / 3600
    day = index // DAY_BUCKETS
    # 2025-01-01 was a Wednesday; days 4 and 5 of the corpus are the weekend.
    weekend = (day + 2) % 7 in (5, 6)
    shape = 0.08 + 0.92 * math.sin(math.pi * min(max(hour - 6, 0), 14) / 14) ** 2
    return shape * (host.weekend_factor if weekend else 1.0)


def window_for(host: Host, index: int) -> Window | None:
    day = index // DAY_BUCKETS
    hour = ((index % DAY_BUCKETS) * BUCKET_SECONDS) / 3600
    for window in host.windows:
        if window.day == day and window.start_hour <= hour < (
            window.start_hour + window.hours
        ):
            return window
    return None


def build_host(host: Host, rng: random.Random) -> dict[str, list[float]]:
    series: dict[str, list[float]] = {metric: [] for metric in METRICS}
    for index in range(TOTAL):
        day = index // DAY_BUCKETS
        if day < host.active_from_day:
            for metric in METRICS:
                series[metric].append(0.0)
            continue

        shape = diurnal(index, host)
        jitter = 1.0 + rng.gauss(0, host.noise)
        conns = max(0.0, host.base_conns * shape * jitter)
        destinations = max(
            0.0, host.base_destinations * shape * (1.0 + rng.gauss(0, 0.3))
        )
        per_conn = host.bytes_per_conn * (1.0 + rng.gauss(0, 0.35))

        window = window_for(host, index)
        if window is not None:
            conns *= window.conn_multiplier
            per_conn *= window.bytes_multiplier
            if window.destinations is not None:
                destinations = window.destinations * (
                    1.0 + rng.gauss(0, 0.15)
                )

        series["conn_count"].append(round(conns, 2))
        series["bytes_out"].append(round(max(0.0, conns * per_conn), 1))
        series["distinct_destinations"].append(
            float(max(0, round(min(destinations, conns if conns > 1 else 1))))
        )
    return series


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination", type=Path, default=Path("fixtures/timeseries")
    )
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)

    corpus: dict[str, object] = {
        "generated_by": "scripts/generate_timeseries_corpus.py",
        "seed": args.seed,
        "start": START.isoformat(),
        "bucket_seconds": BUCKET_SECONDS,
        "buckets": TOTAL,
        "days": DAYS,
        "metrics": list(METRICS),
        "hosts": {},
    }
    labels: list[dict[str, object]] = []

    for host in HOSTS:
        rng = random.Random(f"{args.seed}:{host.entity}")
        corpus["hosts"][host.entity] = {
            "profile": host.profile,
            "note": host.note,
            "active_from_day": host.active_from_day,
            "series": build_host(host, rng),
        }
        for window in host.windows:
            begin = START + timedelta(
                days=window.day, hours=window.start_hour
            )
            labels.append({
                "entity": host.entity,
                "category": window.category,
                "malicious": window.malicious,
                "start": begin.isoformat(),
                "end": (begin + timedelta(hours=window.hours)).isoformat(),
            })

    corpus_path = args.destination / "corpus.json"
    corpus_path.write_text(
        json.dumps(corpus, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    labels_path = args.destination / "labels.json"
    labels_path.write_text(
        json.dumps(
            {
                "note": (
                    "malicious=false entries are benign activity that looks "
                    "anomalous. Flagging them is a false positive."
                ),
                "windows": sorted(
                    labels, key=lambda item: (item["entity"], item["start"])
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    malicious = sum(1 for item in labels if item["malicious"])
    print(f"Wrote {corpus_path} ({corpus_path.stat().st_size / 1024:.0f} KiB)")
    print(f"Wrote {labels_path}")
    print(
        f"{len(HOSTS)} hosts, {TOTAL} buckets each, "
        f"{malicious} malicious and {len(labels) - malicious} benign windows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
