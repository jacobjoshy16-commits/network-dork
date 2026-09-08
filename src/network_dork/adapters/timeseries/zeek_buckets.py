"""Bucket existing Zeek connection logs into regular per-entity series.

This is read-only aggregation over logs that already exist. It computes no
detections and derives no alert conditions; it counts and sums what is there.

Scanning a connection log once per metric is acceptable for the fixture
corpus and small deployments. Production volumes need an indexed source (the
OpenSearch provider) or a pre-aggregated bucket store: a full scan per alert
per metric does not scale, and that limit is documented rather than hidden.
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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if min_observations < 1:
            raise ValueError("min_observations must be positive")
        if not 0 < min_span_fraction <= 1:
            raise ValueError("min_span_fraction must be within (0, 1]")
        self.path = Path(directory) / filename
        self.regularity_window = regularity_window
        self.min_observations = min_observations
        self.min_span_fraction = min_span_fraction
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
        totals = [0.0] * buckets
        distinct: list[set[str]] = [set() for _ in range(buckets)]
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
                if kind in ("count", "regularity"):
                    totals[index] += 1.0
                elif kind == "sum":
                    raw = row.get(field, 0)
                    totals[index] += float(raw) if raw is not None else 0.0
                else:
                    value = row.get(field)
                    if value is not None:
                        distinct[index].add(str(value))

        if kind == "distinct":
            totals = [float(len(bucket)) for bucket in distinct]
        elif kind == "regularity":
            totals = rolling_regularity(totals, self.regularity_window)

        # Zero-filled buckets are not history. Forecasting a mostly-empty
        # series makes any real traffic look like a large deviation, which is
        # the fastest way to generate false positives. Require both enough
        # observations and enough calendar coverage before forecasting at all.
        if observed < self.min_observations:
            raise InsufficientHistory(
                f"{entity}/{metric} has {observed} observations; "
                f"{self.min_observations} are required"
            )
        window = (end - start).total_seconds()
        span = (latest - earliest).total_seconds() if earliest and latest else 0
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
