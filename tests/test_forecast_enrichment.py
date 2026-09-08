"""Forecast enrichment: bucketing, scoring, and the enrichment boundary.

The boundary properties matter as much as the arithmetic. Enrichment must add
a fifth evidence kind without creating alerts, without changing the other four,
and without failing an investigation when the forecaster is unavailable.
"""

from datetime import datetime, timedelta, timezone
import json
import math

import httpx
import pytest

from network_dork.adapters.context.forecast import (
    ForecastEnrichingContextProvider,
)
from network_dork.adapters.context.null import NullContextProvider
from network_dork.adapters.forecast.timesfm_http import (
    ForecastServiceError,
    TimesFMForecaster,
)
from network_dork.adapters.timeseries.zeek_buckets import (
    ZeekBucketTimeSeriesProvider,
)
from network_dork.anomaly import (
    InsufficientHistory,
    SeasonalNaiveForecaster,
    most_deviant,
    score,
)
from network_dork.audit import JsonlAuditLog
from network_dork.models import Alert, Forecast, TimeSeries

ALERT_TIME = datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc)
BUCKET = 300
PERIOD = 288  # one day at five-minute buckets


def alert(src_ip: str | None = "10.77.0.1") -> Alert:
    return Alert(
        source="synthetic",
        alert_id="syn-001",
        timestamp=ALERT_TIME,
        title="Periodic callback alert",
        description="",
        src_ip=src_ip,
        dst_ip=None,
        host="workstation-01.test" if src_ip is None else None,
        domains=[],
        original={},
    )


def daily_series(days: int, *, spike_at: int | None = None) -> TimeSeries:
    """A believable diurnal series: low overnight, busy in working hours."""
    values: list[float] = []
    for index in range(days * PERIOD):
        hour = ((index % PERIOD) * BUCKET) / 3600
        base = 10 + 40 * math.sin(math.pi * max(hour - 6, 0) / 12) ** 2
        values.append(round(base, 3))
    if spike_at is not None:
        for offset in range(12):
            values[spike_at + offset] *= 9
    return TimeSeries(
        metric="conn_count",
        entity="10.77.0.1",
        bucket_seconds=BUCKET,
        start=ALERT_TIME - timedelta(seconds=BUCKET * days * PERIOD),
        values=values,
    )


# --- baseline forecaster ----------------------------------------------------


def test_baseline_predicts_a_stable_series_within_its_own_band():
    series = daily_series(5)
    forecaster = SeasonalNaiveForecaster(period_buckets=PERIOD)
    prediction = forecaster.forecast(series, 12)

    assert prediction.model == "seasonal-naive"
    assert len(prediction.median) == 12
    for low, high in zip(prediction.lower, prediction.upper):
        assert low <= high


def test_baseline_refuses_a_series_without_enough_history():
    short = daily_series(1)
    forecaster = SeasonalNaiveForecaster(period_buckets=PERIOD)
    with pytest.raises(InsufficientHistory):
        forecaster.forecast(short, 12)


def test_a_quiet_series_scores_zero_and_a_spike_scores_high():
    series = daily_series(5)
    forecaster = SeasonalNaiveForecaster(period_buckets=PERIOD)
    history = series.model_copy(update={"values": series.values[:-12]})
    prediction = forecaster.forecast(history, 12)

    quiet = score(
        series=series,
        actual=series.values[-12:],
        forecast=prediction,
        first_index=len(series.values) - 12,
    )
    assert all(point.score == 0.0 for point in quiet)

    spiked = [value * 9 for value in series.values[-12:]]
    loud = score(
        series=series,
        actual=spiked,
        forecast=prediction,
        first_index=len(series.values) - 12,
    )
    assert all(point.score > 0 for point in loud)
    assert all(point.direction == "above_forecast" for point in loud)


def test_most_deviant_returns_only_real_deviations_oldest_first():
    series = daily_series(5)
    forecaster = SeasonalNaiveForecaster(period_buckets=PERIOD)
    history = series.model_copy(update={"values": series.values[:-12]})
    prediction = forecaster.forecast(history, 12)
    actual = list(series.values[-12:])
    actual[3] *= 20
    points = score(
        series=series,
        actual=actual,
        forecast=prediction,
        first_index=len(series.values) - 12,
    )
    top = most_deviant(points, 5)
    assert len(top) == 1
    assert top[0].score > 0
    assert top == sorted(top, key=lambda item: item.timestamp)


# --- bucketizer -------------------------------------------------------------


def write_conn_log(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def test_bucketizer_counts_connections_into_regular_buckets(tmp_path):
    rows = []
    for minute in (2, 3, 9, 9, 9):
        rows.append({
            "ts": (ALERT_TIME - timedelta(minutes=15 - minute)).isoformat(),
            "id.orig_h": "10.77.0.1",
            "id.resp_h": "192.0.2.1",
            "orig_bytes": 100,
        })
    write_conn_log(tmp_path / "zeek" / "conn.log", rows)

    provider = ZeekBucketTimeSeriesProvider(
        tmp_path / "zeek", min_observations=1, min_span_fraction=0.01
    )
    series = provider.series(
        metric="conn_count",
        entity="10.77.0.1",
        end=ALERT_TIME,
        buckets=3,
        bucket_seconds=BUCKET,
    )
    assert series.values == [2.0, 3.0, 0.0]
    assert series.bucket_seconds == BUCKET


def test_bucketizer_reports_no_history_rather_than_an_empty_series(tmp_path):
    write_conn_log(tmp_path / "zeek" / "conn.log", [])
    provider = ZeekBucketTimeSeriesProvider(
        tmp_path / "zeek", min_observations=1, min_span_fraction=0.01
    )
    with pytest.raises(InsufficientHistory):
        provider.series(
            metric="conn_count",
            entity="10.77.0.1",
            end=ALERT_TIME,
            buckets=3,
            bucket_seconds=BUCKET,
        )


def test_bucketizer_counts_distinct_destinations(tmp_path):
    rows = [
        {
            "ts": (
                ALERT_TIME - timedelta(minutes=4) + timedelta(seconds=index * 30)
            ).isoformat(),
            "id.orig_h": "10.77.0.1",
            "id.resp_h": destination,
        }
        for index, destination in enumerate(
            ("192.0.2.1", "192.0.2.2", "192.0.2.1")
        )
    ]
    write_conn_log(tmp_path / "zeek" / "conn.log", rows)
    provider = ZeekBucketTimeSeriesProvider(
        tmp_path / "zeek", min_observations=1, min_span_fraction=0.01
    )
    series = provider.series(
        metric="distinct_destinations",
        entity="10.77.0.1",
        end=ALERT_TIME,
        buckets=1,
        bucket_seconds=BUCKET,
    )
    assert series.values == [2.0]


# --- enrichment boundary ----------------------------------------------------


class SeriesProvider:
    def __init__(self, series: TimeSeries | None, error: Exception | None = None):
        self._series = series
        self._error = error

    def series(self, *, metric, entity, end, buckets, bucket_seconds):
        if self._error is not None:
            raise self._error
        assert self._series is not None
        return self._series.model_copy(
            update={
                "metric": metric,
                "values": self._series.values[-buckets:],
            }
        )


class BrokenForecaster:
    def forecast(self, series, horizon):
        raise RuntimeError("forecast sidecar is unreachable")


def build_provider(tmp_path, series_provider, forecaster, **kwargs):
    return ForecastEnrichingContextProvider(
        NullContextProvider(),
        series_provider,
        forecaster,
        JsonlAuditLog(tmp_path / "audit.jsonl"),
        metrics=["conn_count"],
        bucket_seconds=BUCKET,
        history_buckets=PERIOD * 3,
        horizon_buckets=12,
        **kwargs,
    )


def test_enrichment_adds_forecast_evidence_without_touching_other_kinds(tmp_path):
    series = daily_series(4)
    spiked = list(series.values)
    for index in range(-12, 0):
        spiked[index] *= 9
    provider = build_provider(
        tmp_path,
        SeriesProvider(series.model_copy(update={"values": spiked})),
        SeasonalNaiveForecaster(period_buckets=PERIOD),
    )
    context = provider.gather(alert())

    assert context.forecast, "expected forecast evidence for a clear spike"
    assert all(record.kind == "forecast" for record in context.forecast)
    assert "forecast" not in context.unavailable
    # The wrapped provider's verdict is untouched.
    baseline = NullContextProvider().gather(alert())
    assert context.flows == baseline.flows
    assert context.dns == baseline.dns
    assert context.auth == baseline.auth
    assert context.prior_alert_count == baseline.prior_alert_count


def test_forecast_evidence_stays_inside_the_context_window(tmp_path):
    series = daily_series(4)
    spiked = list(series.values)
    for index in range(-12, 0):
        spiked[index] *= 9
    provider = build_provider(
        tmp_path,
        SeriesProvider(series.model_copy(update={"values": spiked})),
        SeasonalNaiveForecaster(period_buckets=PERIOD),
    )
    context = provider.gather(alert())
    for record in context.forecast:
        assert context.window_start <= record.timestamp <= context.window_end


def test_a_forecaster_outage_marks_context_unavailable_not_failed(tmp_path):
    provider = build_provider(
        tmp_path, SeriesProvider(daily_series(4)), BrokenForecaster()
    )
    context = provider.gather(alert())
    assert context.forecast == []
    assert "forecast" in context.unavailable
    # The rest of the investigation is unaffected.
    assert context.alert.alert_id == "syn-001"


def test_insufficient_history_is_explicit_rather_than_a_guess(tmp_path):
    provider = build_provider(
        tmp_path,
        SeriesProvider(None, InsufficientHistory("only 3 days of history")),
        SeasonalNaiveForecaster(period_buckets=PERIOD),
    )
    context = provider.gather(alert())
    assert context.forecast == []
    assert "forecast" in context.unavailable


def test_an_alert_without_an_ip_is_marked_unavailable(tmp_path):
    provider = build_provider(
        tmp_path,
        SeriesProvider(daily_series(4)),
        SeasonalNaiveForecaster(period_buckets=PERIOD),
    )
    context = provider.gather(alert(src_ip=None))
    assert context.forecast == []
    assert "no IP" in context.unavailable["forecast"]


def test_forecast_evidence_is_labelled_as_an_observation_not_a_detection(tmp_path):
    series = daily_series(4)
    spiked = list(series.values)
    for index in range(-12, 0):
        spiked[index] *= 9
    provider = build_provider(
        tmp_path,
        SeriesProvider(series.model_copy(update={"values": spiked})),
        SeasonalNaiveForecaster(period_buckets=PERIOD),
    )
    context = provider.gather(alert())
    for record in context.forecast:
        assert "not a detection" in record.fields["note"].lower()
        assert {"observed", "predicted", "predicted_range"} <= set(record.fields)


# --- TimesFM client ---------------------------------------------------------


def timesfm_client(handler):
    return TimesFMForecaster(
        base_url="http://127.0.0.1:11435",
        transport=httpx.MockTransport(handler),
    )


def test_timesfm_client_parses_a_well_formed_forecast():
    def handler(request):
        body = json.loads(request.content)
        horizon = body["horizon"]
        return httpx.Response(200, json={
            "model": "timesfm-2.5-200m",
            "model_digest": "abc123",
            "median": [1.0] * horizon,
            "lower": [0.5] * horizon,
            "upper": [1.5] * horizon,
        })

    client = timesfm_client(handler)
    try:
        prediction = client.forecast(daily_series(2), 4)
    finally:
        client.close()
    assert isinstance(prediction, Forecast)
    assert prediction.model_digest == "abc123"
    assert len(prediction.median) == 4


def test_timesfm_client_refuses_non_commercial_weights():
    def handler(request):
        horizon = json.loads(request.content)["horizon"]
        return httpx.Response(200, json={
            "model": "timesfm-3.0-200m",
            "model_digest": None,
            "median": [1.0] * horizon,
            "lower": [0.0] * horizon,
            "upper": [2.0] * horizon,
        })

    client = timesfm_client(handler)
    try:
        with pytest.raises(ForecastServiceError, match="non-commercial"):
            client.forecast(daily_series(2), 4)
    finally:
        client.close()


def test_timesfm_client_rejects_a_malformed_band():
    def handler(request):
        return httpx.Response(200, json={
            "model": "timesfm-2.5-200m",
            "median": [1.0, 2.0],
            "lower": [0.0],
            "upper": [3.0, 4.0],
        })

    client = timesfm_client(handler)
    try:
        with pytest.raises(ForecastServiceError, match="malformed"):
            client.forecast(daily_series(2), 2)
    finally:
        client.close()


def test_timesfm_client_refuses_a_public_endpoint():
    from network_dork.config import LocalEndpointError

    with pytest.raises(LocalEndpointError):
        TimesFMForecaster(base_url="http://8.8.8.8:11435")


# --- prompt budget ----------------------------------------------------------


def test_a_fully_loaded_enriched_prompt_fits_the_default_input_budget():
    """Evidence caps must keep an enriched prompt inside the model's budget.

    Found end to end rather than in a unit test: with uncapped evidence a
    realistic host produced a 3.4M-character prompt, which would fail every
    enriched investigation with an input-limit error.
    """
    from network_dork.config import ContextSettings, LLMSettings
    from network_dork.models import AlertContext, EvidenceRecord
    from network_dork.prompts import SYSTEM_PROMPT, InvestigationPrompt

    cap = ContextSettings().max_records
    budget = LLMSettings().max_input_chars

    def flow(index: int, kind: str) -> EvidenceRecord:
        moment = ALERT_TIME - timedelta(minutes=index + 1)
        return EvidenceRecord(
            evidence_id=f"{kind}:conn.log:{index}",
            kind=kind,
            source=f"fixtures/zeek/conn.log:{index}",
            timestamp=moment,
            fields={
                "ts": moment.isoformat(),
                "id.orig_h": "10.77.0.1",
                "id.resp_h": "192.0.2.1",
                "id.orig_p": 44821,
                "id.resp_p": 443,
                "proto": "tcp",
                "orig_bytes": 5210,
                "resp_bytes": 1180,
                "conn_state": "SF",
                "duration": 1.42,
            },
        )

    context = AlertContext(
        alert=alert(),
        window_start=ALERT_TIME - timedelta(days=7),
        window_end=ALERT_TIME,
        flows=[flow(i, "flows") for i in range(cap)],
        dns=[flow(i, "dns") for i in range(cap)],
        auth=[flow(i, "auth") for i in range(cap)],
        forecast=[flow(i, "forecast") for i in range(cap)],
        prior_alert_count=3,
        unavailable={},
        truncated={"flows": 4000},
    )
    system, user = InvestigationPrompt("qwen2.5:3b-instruct").render(context)
    assert len(system) + len(user) < budget, (
        f"a full context renders {len(system) + len(user):,} chars against a "
        f"{budget:,} budget; lower context.max_records or raise llm.num_ctx"
    )


def test_truncated_evidence_counts_reach_the_model():
    """The model must be told what it is not seeing."""
    from network_dork.models import AlertContext
    from network_dork.prompts import InvestigationPrompt

    context = AlertContext(
        alert=alert(),
        window_start=ALERT_TIME - timedelta(days=7),
        window_end=ALERT_TIME,
        flows=[],
        dns=[],
        auth=[],
        prior_alert_count=0,
        unavailable={},
        truncated={"flows": 11246},
    )
    _, user = InvestigationPrompt("m").render(context)
    assert json.loads(user)["supplied_context"]["truncated"]["flows"] == 11246


def test_a_sparse_host_is_refused_rather_than_zero_filled(tmp_path):
    """Zero-padding is not history.

    Found by running the CLI against the fixture corpus: a host with a
    handful of connections produced a 14-day series that was almost entirely
    zeros, and every real connection then scored as a large deviation. That
    is a false-positive generator, so coverage is checked before forecasting.
    """
    rows = [
        {
            "ts": (ALERT_TIME - timedelta(minutes=index + 1)).isoformat(),
            "id.orig_h": "10.77.0.1",
            "id.resp_h": "192.0.2.1",
        }
        for index in range(20)
    ]
    write_conn_log(tmp_path / "zeek" / "conn.log", rows)
    provider = ZeekBucketTimeSeriesProvider(tmp_path / "zeek")

    with pytest.raises(InsufficientHistory, match="observations"):
        provider.series(
            metric="conn_count",
            entity="10.77.0.1",
            end=ALERT_TIME,
            buckets=PERIOD * 14,
            bucket_seconds=BUCKET,
        )


def test_a_host_active_only_recently_is_refused(tmp_path):
    """Enough rows, but all crammed into the last hour of a 14-day window."""
    rows = [
        {
            "ts": (ALERT_TIME - timedelta(seconds=index * 20)).isoformat(),
            "id.orig_h": "10.77.0.1",
            "id.resp_h": "192.0.2.1",
        }
        for index in range(1, 200)
    ]
    write_conn_log(tmp_path / "zeek" / "conn.log", rows)
    provider = ZeekBucketTimeSeriesProvider(tmp_path / "zeek")

    with pytest.raises(InsufficientHistory, match="zero-filled"):
        provider.series(
            metric="conn_count",
            entity="10.77.0.1",
            end=ALERT_TIME,
            buckets=PERIOD * 14,
            bucket_seconds=BUCKET,
        )


def test_a_quiet_period_does_not_collapse_the_band():
    """A host idle overnight must not flag on its first morning connection.

    Found by running against generated telemetry rather than a test fixture:
    a bucket predicted at zero got a zero-width band from a purely relative
    floor, so any traffic at all scored as a huge deviation.
    """
    quiet_nights = []
    for day in range(5):
        for index in range(PERIOD):
            hour = (index * BUCKET) / 3600
            quiet_nights.append(0.0 if hour < 7 or hour > 19 else 20.0)
    series = TimeSeries(
        metric="conn_count",
        entity="10.77.0.1",
        bucket_seconds=BUCKET,
        start=ALERT_TIME - timedelta(seconds=BUCKET * len(quiet_nights)),
        values=quiet_nights,
    )
    prediction = SeasonalNaiveForecaster(period_buckets=PERIOD).forecast(
        series, 12
    )
    assert all(
        high > low for low, high in zip(prediction.lower, prediction.upper)
    ), "a zero prediction must still produce a band with width"


def test_ordinary_traffic_after_a_quiet_night_scores_zero():
    values = []
    for day in range(5):
        for index in range(PERIOD):
            hour = (index * BUCKET) / 3600
            values.append(0.0 if hour < 7 else 20.0)
    series = TimeSeries(
        metric="conn_count",
        entity="10.77.0.1",
        bucket_seconds=BUCKET,
        start=ALERT_TIME - timedelta(seconds=BUCKET * len(values)),
        values=values,
    )
    history = series.model_copy(update={"values": values[:-12]})
    prediction = SeasonalNaiveForecaster(period_buckets=PERIOD).forecast(
        history, 12
    )
    points = score(
        series=series,
        actual=values[-12:],
        forecast=prediction,
        first_index=len(values) - 12,
    )
    assert max(point.score for point in points) < 4.0


def test_a_negative_band_edge_is_hidden_from_the_analyst_not_from_scoring():
    """"expected -0.4 connections" reads as a broken tool, so it is clamped
    for display. Clamping it in the forecaster instead was measured and made
    accuracy worse: the narrower band took the evaluation corpus from zero
    false positives to seven.
    """
    from network_dork.models import AlertContext, EvidenceRecord
    from network_dork.render import render_forecast

    context = AlertContext(
        alert=alert(),
        window_start=ALERT_TIME - timedelta(days=7),
        window_end=ALERT_TIME,
        flows=[],
        dns=[],
        auth=[],
        forecast=[
            EvidenceRecord(
                evidence_id="forecast:conn_count:x",
                kind="forecast",
                source="forecast:test",
                timestamp=ALERT_TIME - timedelta(hours=1),
                fields={
                    "metric": "conn_count",
                    "observed": 12.0,
                    "predicted": 0.0,
                    "predicted_range": [-0.4, 0.4],
                    "deviation_score": 14.5,
                    "direction": "above_forecast",
                    "note": "Not a detection.",
                },
            )
        ],
        prior_alert_count=0,
        unavailable={},
    )
    rendered = render_forecast(context)
    assert "-0.4" not in rendered
    assert "0.0 to 0.4" in rendered
