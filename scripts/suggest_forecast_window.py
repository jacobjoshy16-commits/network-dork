#!/usr/bin/env python3
"""Report what a Zeek conn.log can and cannot support a forecast of.

The shipped forecast window is fourteen days at five-minute buckets, which is
what a baseline for a production host should be. A capture taken this
afternoon cannot meet it, and `readiness` will say so.

That is the right default and the wrong thing to leave someone stuck behind
when the question is whether the mechanism works on their own telemetry at
all. The forecaster's requirements are relative -- enough buckets, spanning
enough of the requested window -- so a shorter bucket over a shorter history
satisfies the same arithmetic on a shorter capture.

What that buys and what it does not:

* it buys a real forecast, from real packets, through the real adapter, with
  real deviation scores -- the mechanism, demonstrated end to end;
* it does not buy a baseline. Fourteen days of a host's behaviour tells you
  what is normal for it. Twenty minutes tells you what it did for twenty
  minutes. Deviation scores computed against a minutes-long history are
  illustrative of the pipeline and are not evidence about the traffic.

So this prints the settings and prints the caveat with them, and the overlay
it writes carries the caveat in a comment, because the number is only honest
next to the sentence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Below this the arithmetic is satisfiable but meaningless: a handful of
# buckets makes every value both the history and the anomaly.
MIN_USEFUL_BUCKETS = 40


def spans(path: Path) -> tuple[float, float, int]:
    """Return (first_ts, last_ts, rows) from a JSON-lines conn.log."""
    first: float | None = None
    last: float | None = None
    rows = 0
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                timestamp = float(json.loads(line)["ts"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
            rows += 1
            if first is None or timestamp < first:
                first = timestamp
            if last is None or timestamp > last:
                last = timestamp
    if first is None or last is None:
        raise SystemExit(
            f"{path}: no usable rows. Zeek must be run with "
            "LogAscii::use_json=T for this project to read its logs."
        )
    return first, last, rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--conn-log",
        type=Path,
        default=Path("var/real/conn.log"),
        help="JSON-lines Zeek conn.log to measure.",
    )
    parser.add_argument(
        "--write-overlay",
        type=Path,
        default=None,
        help="Write a config overlay with the derived settings.",
    )
    parser.add_argument(
        "--min-observations",
        type=int,
        default=100,
        help="Buckets the forecaster must see. Mirrors forecast.min_observations.",
    )
    args = parser.parse_args()

    first, last, rows = spans(args.conn_log)
    span = last - first
    print(f"{args.conn_log}: {rows:,} rows spanning {span / 60:.1f} minutes")

    if span <= 0:
        raise SystemExit("All rows share one timestamp; nothing to bucket.")

    # Default gates, for the comparison that explains the verdict.
    print("\nAgainst the shipped fourteen-day window:")
    default_span_needed = 4032 * 300 * 0.5
    print(
        f"  needs a span of {default_span_needed / 86400:.1f} days; "
        f"this capture spans {span / 86400:.4f} days  -> not eligible"
    )

    # The forecaster needs min_observations buckets, and the span must cover
    # min_span_fraction of history_buckets * bucket_seconds. Pick the bucket
    # so the capture fills the whole history window exactly.
    history = max(args.min_observations, MIN_USEFUL_BUCKETS)
    bucket = max(1, int(span // history))
    horizon = max(1, history // 10)
    period = max(2, history // 4)
    usable = int(span // bucket)

    print("\nA window this capture does satisfy:")
    print(f"  bucket_seconds    {bucket}")
    print(f"  history_buckets   {history}")
    print(f"  horizon_buckets   {horizon}   (the window scored for deviation)")
    print(f"  period_buckets    {period}")
    print(f"  -> about {usable} buckets of data")

    if usable < MIN_USEFUL_BUCKETS:
        print(
            f"\nRefusing to suggest these: {usable} buckets is too few to "
            "distinguish history from anomaly. Capture for longer."
        )
        return 1

    print(
        "\nWhat this demonstrates: the forecaster runs on your own packets,\n"
        "end to end, and produces real deviation scores.\n"
        "What it does NOT demonstrate: that those scores mean anything about\n"
        f"the traffic. A {span / 60:.0f}-minute history is not a baseline for a\n"
        "host's normal behaviour. Present it as the mechanism working, never\n"
        "as a detection rate, and keep the fourteen-day default for anything\n"
        "you intend to trust."
    )

    if args.write_overlay is not None:
        args.write_overlay.parent.mkdir(parents=True, exist_ok=True)
        args.write_overlay.write_text(
            "# Generated by scripts/suggest_forecast_window.py.\n"
            "#\n"
            "# A short-window overlay for demonstrating the forecast path on a\n"
            f"# {span / 60:.0f}-minute capture ({rows:,} conn.log rows).\n"
            "#\n"
            "# This is a MECHANISM DEMO, not a baseline. Deviation scores from a\n"
            "# history this short describe what the host did for a few minutes,\n"
            "# not what is normal for it. Do not quote them as accuracy, and do\n"
            "# not deploy this overlay.\n"
            "forecast:\n"
            f"  bucket_seconds: {bucket}\n"
            f"  history_buckets: {history}\n"
            f"  horizon_buckets: {horizon}\n"
            f"  period_buckets: {period}\n"
            f"  min_observations: {min(args.min_observations, usable // 2)}\n"
            "  min_span_fraction: 0.5\n"
            "  baseline_started_at: null\n",
            encoding="utf-8",
        )
        print(f"\nWrote {args.write_overlay}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
