#!/usr/bin/env python3
"""Merge many Zeek capture sessions into one directory the adapters can read.

Live capture on a laptop is not one long session. Zeek stops when the machine
sleeps, when the interface changes, and when the terminal closes, and each
restart writes a fresh conn.log rather than appending to the last one. The
context provider reads a single directory, so a week of real collection
arrives as a pile of directories it cannot use.

This concatenates them in timestamp order and reports what the result spans,
which is the number that decides whether the forecaster is eligible at all.

Rows are passed through untouched. Duplicates are dropped only when a whole
line repeats byte for byte, which happens when a session directory is merged
twice; two genuinely distinct connections with identical fields would be
distinguished by their uid, so nothing real is lost.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# The logs this project's adapters read. Others are left where they are.
LOG_NAMES = ("conn.log", "dns.log", "auth.log", "ssl.log", "http.log")


def merge(paths: list[Path], destination: Path) -> tuple[int, float | None, float | None]:
    """Write timestamp-ordered unique rows to destination."""
    rows: list[tuple[float, str]] = []
    seen: set[str] = set()
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                stripped = line.strip()
                if not stripped or stripped in seen:
                    continue
                try:
                    timestamp = float(json.loads(stripped)["ts"])
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
                seen.add(stripped)
                rows.append((timestamp, stripped))

    rows.sort(key=lambda item: item[0])
    destination.write_text(
        "".join(f"{line}\n" for _, line in rows), encoding="utf-8"
    )
    if not rows:
        return 0, None, None
    return len(rows), rows[0][0], rows[-1][0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sessions",
        type=Path,
        default=Path("var/live"),
        help="Directory holding one subdirectory per capture session.",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path("var/live/merged"),
        help="Directory to write the merged logs into.",
    )
    args = parser.parse_args()

    if not args.sessions.is_dir():
        raise SystemExit(f"{args.sessions} is not a directory")

    args.destination.mkdir(parents=True, exist_ok=True)
    overall_first: float | None = None
    overall_last: float | None = None
    merged_any = False

    for name in LOG_NAMES:
        paths = sorted(
            path
            for path in args.sessions.glob(f"*/{name}")
            if path.parent.resolve() != args.destination.resolve()
        )
        if not paths:
            continue
        count, first, last = merge(paths, args.destination / name)
        merged_any = True
        span = "" if first is None else f", {(last - first) / 3600:.1f} h"
        print(f"{name:<10} {count:>9,} rows from {len(paths)} session(s){span}")
        if first is not None:
            overall_first = first if overall_first is None else min(overall_first, first)
            overall_last = last if overall_last is None else max(overall_last, last)

    if not merged_any:
        raise SystemExit(
            f"No {' / '.join(LOG_NAMES)} found under {args.sessions}/*/. "
            "Zeek must be run with LogAscii::use_json=T."
        )

    if overall_first is not None and overall_last is not None:
        days = (overall_last - overall_first) / 86400
        print(f"\nmerged span: {days:.2f} days -> {args.destination}")
        # The gate that actually decides eligibility, stated once here so it
        # does not have to be rediscovered from config every time.
        needed = 4032 * 300 * 0.5 / 86400
        if days >= needed:
            print(
                f"That clears the {needed:.1f}-day minimum for the shipped "
                "fourteen-day window. Point NETWORK_DORK_ZEEK_DIRECTORY here "
                "and run readiness."
            )
        else:
            print(
                f"The shipped window needs {needed:.1f} days; keep collecting. "
                "For a mechanism demo before then, see "
                "scripts/suggest_forecast_window.py."
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
