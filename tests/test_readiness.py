"""History accumulation: coverage reporting and the baseline period.

Neither forecaster learns anything. TimesFM is frozen and zero-shot, and the
baseline is arithmetic over a window. What a new deployment waits for is
telemetry to accumulate, and these make that wait visible instead of
something an operator discovers one alert at a time.
"""

from datetime import datetime, timedelta, timezone
import json

import pytest

from network_dork.adapters.context.forecast import (
    ForecastEnrichingContextProvider,
)
from network_dork.adapters.context.null import NullContextProvider
from network_dork.adapters.timeseries.zeek_buckets import (
    ZeekBucketTimeSeriesProvider,
)
from network_dork.anomaly import SeasonalNaiveForecaster
from network_dork.audit import JsonlAuditLog
from network_dork.models import Alert

NOW = datetime(2025, 2, 1, 12, 0, tzinfo=timezone.utc)
BUCKET = 300
PERIOD = 288
HISTORY = PERIOD * 14


def alert(when: datetime = NOW) -> Alert:
    return Alert(
        source="synthetic",
        alert_id="syn-001",
        timestamp=when,
        title="Alert",
        description="",
        src_ip="10.20.0.5",
        dst_ip=None,
        host=None,
        domains=[],
        original={},
    )


def write_log(path, entity: str, days: float, end: datetime = NOW):
    path.parent.mkdir(parents=True, exist_ok=True)
    buckets = int(days * PERIOD)
    with path.open("w", encoding="utf-8") as stream:
        for index in range(buckets):
            moment = end - timedelta(seconds=BUCKET * (buckets - index))
            for offset in range(4):
                stream.write(json.dumps({
                    "ts": (moment + timedelta(seconds=offset)).isoformat(),
                    "id.orig_h": entity,
                    "id.resp_h": "192.0.2.9",
                    "orig_bytes": 400,
                }) + "\n")


# --- coverage ---------------------------------------------------------------


def test_a_host_with_long_history_reports_ready(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    provider = ZeekBucketTimeSeriesProvider(tmp_path / "zeek")
    report = provider.coverage(
        end=NOW, buckets=HISTORY, bucket_seconds=BUCKET
    )
    assert report["10.20.0.5"].ready
    assert report["10.20.0.5"].reason() == "ready"


def test_a_new_host_reports_how_much_longer_it_needs(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=3)
    provider = ZeekBucketTimeSeriesProvider(tmp_path / "zeek")
    report = provider.coverage(
        end=NOW, buckets=HISTORY, bucket_seconds=BUCKET
    )
    coverage = report["10.20.0.5"]
    assert not coverage.ready
    assert coverage.days_remaining > 0
    assert "more days needed" in coverage.reason()


def test_coverage_of_a_missing_log_is_empty_not_an_error(tmp_path):
    provider = ZeekBucketTimeSeriesProvider(tmp_path / "absent")
    assert provider.coverage(
        end=NOW, buckets=HISTORY, bucket_seconds=BUCKET
    ) == {}


def test_coverage_counts_both_ends_of_a_connection(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    provider = ZeekBucketTimeSeriesProvider(tmp_path / "zeek")
    report = provider.coverage(
        end=NOW, buckets=HISTORY, bucket_seconds=BUCKET
    )
    assert {"10.20.0.5", "192.0.2.9"} <= set(report)


# --- baseline period --------------------------------------------------------


def build(tmp_path, baseline_started_at):
    return ForecastEnrichingContextProvider(
        NullContextProvider(),
        ZeekBucketTimeSeriesProvider(tmp_path / "zeek"),
        SeasonalNaiveForecaster(period_buckets=PERIOD),
        JsonlAuditLog(tmp_path / "audit.jsonl"),
        metrics=["conn_count"],
        bucket_seconds=BUCKET,
        history_buckets=HISTORY,
        horizon_buckets=72,
        baseline_started_at=baseline_started_at,
    )


def test_enrichment_waits_out_the_baseline_period(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    started = NOW - timedelta(days=3)
    context = build(tmp_path, started).gather(alert())

    assert context.forecast == []
    reason = context.unavailable["forecast"]
    assert "Baseline period is still in progress" in reason
    assert "days" in reason


def test_the_wait_is_reported_with_days_remaining(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    started = NOW - timedelta(days=10)
    reason = build(tmp_path, started).gather(alert()).unavailable["forecast"]
    # 14 days needed, 10 elapsed: about 4 remain.
    assert "4.0 days" in reason


def test_enrichment_proceeds_once_the_baseline_period_has_passed(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    started = NOW - timedelta(days=30)
    context = build(tmp_path, started).gather(alert())
    # Past the gate: whatever it says now is about this host's data, not the
    # deployment's age.
    assert "Baseline period" not in context.unavailable.get("forecast", "")


def test_no_baseline_date_means_no_deployment_wide_gate(tmp_path):
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    context = build(tmp_path, None).gather(alert())
    assert "Baseline period" not in context.unavailable.get("forecast", "")


def test_the_gate_is_evaluated_against_the_alert_not_the_clock(tmp_path):
    """Reprocessing an old alert must not resurrect a finished baseline."""
    write_log(tmp_path / "zeek" / "conn.log", "10.20.0.5", days=20)
    started = NOW - timedelta(days=30)
    early = alert(when=started + timedelta(days=2))
    reason = build(tmp_path, started).gather(early).unavailable["forecast"]
    assert "Baseline period is still in progress" in reason
