"""Bucket existing Zeek connection logs into regular per-entity series.

This is read-only aggregation over logs that already exist. It computes no
detections and derives no alert conditions; it counts and sums what is there.

One alert asks for four metrics over the same host and window, so the log is
scanned once per window and every metric is accumulated in that pass. The
result is cached against the file's size and mtime, which is what makes the
enrichment path cost one scan per alert instead of four.

It is still a full scan. Production volumes need an indexed source (the
OpenSearch provider) or a pre-aggregated bucket store; that limit is
documented rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Callable

from network_dork.anomaly import InsufficientHistory
from network_dork.models import TimeSeries
from network_dork.regularity import rolling_regularity

# Metric name -> (accumulator kind, value extractor)
# "count" adds one per matching row, "sum" adds the extracted number,
# "distinct" counts unique extracted values per bucket, and "regularity"
# counts like "count" then reports how evenly spaced those counts were.
METRICS: dict[str, tuple[str, str]] = {
    "conn_count": ("count", ""),
    "bytes_out": ("sum", "orig_bytes"),
    "distinct_destinations": ("distinct", "id.resp_h"),
    "conn_regularity": ("regularity", ""),
}
# Trailing buckets used to judge regularity. Twelve five-minute buckets is
# one hour: long enough for a rhythm to show, short enough that a beacon
# starting mid-window still moves the number.
REGULARITY_WINDOW = 12


@dataclass(frozen=True)
class Scan:
    """Every metric for one host and window, from a single pass over the log.

    Holding all four together is the point: they differ only in how a row is
    accumulated, so computing one and discarding the parse work needed for
    the others is three quarters of the cost for nothing.
    """

    counts: list[float]
    sums: dict[str, list[float]]
    distinct: dict[str, list[set[str]]]
    observed: int
    earliest: datetime | None
    latest: datetime | None


@dataclass(frozen=True)
class Coverage:
    """How much usable history one host has, and whether it is enough.

    Forecasting needs a host to have been observed for long enough that its
    daily and weekly rhythm is visible. This reports that plainly so an
    operator can see which hosts are ready and which are still accumulating,
    instead of discovering it one alert at a time.
    """

    entity: str
    observations: int
    span_seconds: float
    window_seconds: float
    required_observations: int
    required_span_seconds: float

    @property
    def ready(self) -> bool:
        return (
            self.observations >= self.required_observations
            and self.span_seconds >= self.required_span_seconds
        )

    @property
    def span_days(self) -> float:
        return self.span_seconds / 86400

    @property
    def required_span_days(self) -> float:
        return self.required_span_seconds / 86400

    @property
    def days_remaining(self) -> float:
        """Calendar days of further collection before this host qualifies."""
        return max(0.0, self.required_span_days - self.span_days)

    def reason(self) -> str:
        if self.ready:
            return "ready"
        if self.observations < self.required_observations:
            return (
                f"{self.observations} observations, "
                f"{self.required_observations} required"
            )
        return (
            f"spans {self.span_days:.1f} of {self.required_span_days:.1f} "
            f"days; about {self.days_remaining:.1f} more days needed"
        )


class ZeekBucketTimeSeriesProvider:
    def __init__(
        self,
        directory: str | Path,
        *,
        filename: str = "conn.log",
        regularity_window: int = REGULARITY_WINDOW,
        min_observations: int = 100,
        min_span_fraction: float = 0.5,
        cached_scans: int = 4,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if min_observations < 1:
            raise ValueError("min_observations must be positive")
        if not 0 < min_span_fraction <= 1:
            raise ValueError("min_span_fraction must be within (0, 1]")
        if cached_scans < 1:
            raise ValueError("cached_scans must be positive")
        self.path = Path(directory) / filename
        self.regularity_window = regularity_window
        self.min_observations = min_observations
        self.min_span_fraction = min_span_fraction
        # One alert asks for four metrics over one window, so a handful of
        # entries covers the pattern. Bounded on purpose: an unbounded cache
        # would grow with every alert in a long batch.
        self.cached_scans = cached_scans
        self._scans: dict[tuple, Scan] = {}
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, bool):
            raise ValueError("Boolean is not an event timestamp")
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("Event timestamp has no timezone")
            return parsed
        raise ValueError("Unsupported event timestamp")

    def coverage(
        self,
        *,
        end: datetime,
        buckets: int,
        bucket_seconds: int,
    ) -> dict[str, Coverage]:
        """Report usable history per host in one pass over the log.

        Used by the readiness command so an operator can answer "is my
        network ready for enrichment yet" without processing an alert.
        """
        if buckets < 1 or bucket_seconds < 1:
            raise ValueError("buckets and bucket_seconds must be positive")
        start = end - timedelta(seconds=bucket_seconds * buckets)
        window = float(bucket_seconds * buckets)
        seen: dict[str, list[float]] = {}

        try:
            stream = self.path.open("r", encoding="utf-8")
        except FileNotFoundError:
            return {}

        with stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("Connection log line is not an object")
                timestamp = self._timestamp(row["ts"])
                if not start <= timestamp < end:
                    continue
                moment = timestamp.timestamp()
                for key in ("id.orig_h", "id.resp_h"):
                    entity = str(row.get(key, ""))
                    if not entity:
                        continue
                    record = seen.get(entity)
                    if record is None:
                        seen[entity] = [1.0, moment, moment]
                    else:
                        record[0] += 1
                        record[1] = min(record[1], moment)
                        record[2] = max(record[2], moment)

        return {
            entity: Coverage(
                entity=entity,
                observations=int(count),
                span_seconds=last - first,
                window_seconds=window,
                required_observations=self.min_observations,
                required_span_seconds=window * self.min_span_fraction,
            )
            for entity, (count, first, last) in seen.items()
        }

    def _signature(self) -> tuple[int, int] | None:
        """Size and mtime, so an appended or rotated log is never served stale.

        A live conn.log grows underneath a long-running batch. Keying the
        cache on the file's identity rather than its path means a changed
        file misses instead of returning yesterday's buckets.
        """
        try:
            status = self.path.stat()
        except FileNotFoundError:
            return None
        return (status.st_size, status.st_mtime_ns)

    def _scan(
        self,
        *,
        entity: str,
        end: datetime,
        buckets: int,
        bucket_seconds: int,
    ) -> Scan:
        """Accumulate every metric for one host and window in one pass."""
        key = (entity, end, buckets, bucket_seconds, self._signature())
        cached = self._scans.get(key)
        if cached is not None:
            return cached

        start = end - timedelta(seconds=bucket_seconds * buckets)
        counts = [0.0] * buckets
        sums: dict[str, list[float]] = {
            field: [0.0] * buckets
            for kind, field in METRICS.values()
            if kind == "sum"
        }
        distinct: dict[str, list[set[str]]] = {
            field: [set() for _ in range(buckets)]
            for kind, field in METRICS.values()
            if kind == "distinct"
        }
        observed = 0
        earliest: datetime | None = None
        latest: datetime | None = None

        try:
            stream = self.path.open("r", encoding="utf-8")
        except FileNotFoundError as exc:
            raise InsufficientHistory(
                f"{self.path.name} is unavailable for {entity}"
            ) from exc

        with stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("Connection log line is not an object")
                if entity not in {
                    str(row.get("id.orig_h", "")),
                    str(row.get("id.resp_h", "")),
                }:
                    continue
                timestamp = self._timestamp(row["ts"])
                if not start <= timestamp < end:
                    continue
                index = int(
                    (timestamp - start).total_seconds() // bucket_seconds
                )
                if not 0 <= index < buckets:
                    continue
                observed += 1
                if earliest is None or timestamp < earliest:
                    earliest = timestamp
                if latest is None or timestamp > latest:
                    latest = timestamp
                counts[index] += 1.0
                for field, totals in sums.items():
                    raw = row.get(field, 0)
                    totals[index] += float(raw) if raw is not None else 0.0
                for field, seen in distinct.items():
                    value = row.get(field)
                    if value is not None:
                        seen[index].add(str(value))

        scan = Scan(
            counts=counts,
            sums=sums,
            distinct=distinct,
            observed=observed,
            earliest=earliest,
            latest=latest,
        )
        if len(self._scans) >= self.cached_scans:
            # Oldest first; dicts preserve insertion order.
            del self._scans[next(iter(self._scans))]
        self._scans[key] = scan
        return scan

    def series(
        self,
        *,
        metric: str,
        entity: str,
        end: datetime,
        buckets: int,
        bucket_seconds: int,
    ) -> TimeSeries:
        if metric not in METRICS:
            raise ValueError(f"Unknown metric: {metric}")
        if buckets < 1 or bucket_seconds < 1:
            raise ValueError("buckets and bucket_seconds must be positive")

        kind, field = METRICS[metric]
        start = end - timedelta(seconds=bucket_seconds * buckets)
        scan = self._scan(
            entity=entity,
            end=end,
            buckets=buckets,
            bucket_seconds=bucket_seconds,
        )

        if kind == "count":
            totals = list(scan.counts)
        elif kind == "sum":
            totals = list(scan.sums[field])
        elif kind == "distinct":
            totals = [float(len(bucket)) for bucket in scan.distinct[field]]
        else:
            totals = rolling_regularity(scan.counts, self.regularity_window)

        # Zero-filled buckets are not history. Forecasting a mostly-empty
        # series makes any real traffic look like a large deviation, which is
        # the fastest way to generate false positives. Require both enough
        # observations and enough calendar coverage before forecasting at all.
        if scan.observed < self.min_observations:
            raise InsufficientHistory(
                f"{entity}/{metric} has {scan.observed} observations; "
                f"{self.min_observations} are required"
            )
        window = (end - start).total_seconds()
        span = (
            (scan.latest - scan.earliest).total_seconds()
            if scan.earliest and scan.latest
            else 0
        )
        if span < window * self.min_span_fraction:
            raise InsufficientHistory(
                f"{entity}/{metric} observations span "
                f"{span / 86400:.1f} days of a {window / 86400:.1f}-day "
                "window; the remainder would be zero-filled"
            )

        return TimeSeries(
            metric=metric,
            entity=entity,
            bucket_seconds=bucket_seconds,
            start=start,
            values=totals,
        )
