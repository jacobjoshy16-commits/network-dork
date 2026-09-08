"""The prompt must fit the context window, measured with realistic records.

An earlier version of this check used a thin evidence record and reported
about 380 characters each. Real Zeek flows carry a uid, both endpoints, both
ports, protocol, connection state and byte counts, and cost roughly 1,190.
Understating it by three times is how a limit gets set that does not hold, so
these fixtures mirror what the sample network actually produces.
"""

from datetime import datetime, timedelta, timezone

import pytest

from network_dork.config import (
    CHARS_PER_TOKEN,
    ContextSettings,
    ForecastSettings,
    LLMSettings,
)
from network_dork.models import Alert, AlertContext, EvidenceRecord
from network_dork.prompts import InvestigationPrompt

NOW = datetime(2025, 1, 15, 12, tzinfo=timezone.utc)


def alert() -> Alert:
    return Alert(
        source="sample-sensor",
        alert_id="sample-beacon",
        timestamp=NOW,
        title="Repeated outbound HTTPS to a single destination",
        description="Sensor observed persistent low-volume callbacks.",
        src_ip="10.50.0.21",
        dst_ip="198.51.100.7",
        host="workstation-21.sample",
        domains=["cdn-sync.example.test"],
        original={"sensor_rule": "OUTBOUND_PERSISTENT"},
    )


def flow(index: int, kind: str) -> EvidenceRecord:
    moment = NOW - timedelta(minutes=index + 1)
    return EvidenceRecord(
        evidence_id=f"{kind}:conn.log:{40000 + index}",
        kind=kind,
        source=f"var/sample/zeek/conn.log:{40000 + index}",
        timestamp=moment,
        fields={
            "ts": moment.isoformat(),
            "uid": "C7f3a9b21c04",
            "id.orig_h": "10.50.0.21",
            "id.resp_h": "198.51.100.7",
            "id.orig_p": 44821,
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 5210,
            "resp_bytes": 1180,
        },
    )


def forecast(index: int) -> EvidenceRecord:
    moment = NOW - timedelta(minutes=5 * index + 5)
    return EvidenceRecord(
        evidence_id=f"forecast:conn_regularity:{moment.isoformat()}",
        kind="forecast",
        source="forecast:SeasonalNaiveForecaster:conn_regularity",
        timestamp=moment,
        fields={
            "metric": "conn_regularity",
            "entity": "10.50.0.21",
            "bucket_seconds": 300,
            "observed": 26.0,
            "predicted": 0.2,
            "predicted_range": [0.0, 0.4],
            "deviation_score": 64.0,
            "direction": "above_forecast",
            "note": (
                "Statistical deviation from a predicted range. Not a "
                "detection and not evidence of malicious activity."
            ),
        },
    )


def full_context(records: int, forecasts: int) -> AlertContext:
    return AlertContext(
        alert=alert(),
        window_start=NOW - timedelta(days=7),
        window_end=NOW,
        flows=[flow(i, "flows") for i in range(records)],
        dns=[flow(i, "dns") for i in range(records)],
        auth=[flow(i, "auth") for i in range(records)],
        forecast=[forecast(i) for i in range(forecasts)],
        prior_alert_count=2,
        unavailable={},
        truncated={"flows": 3571},
    )


def prompt_size(context: AlertContext) -> int:
    system, user = InvestigationPrompt("qwen2.5:3b-instruct").render(context)
    return len(system) + len(user)


def test_a_full_context_fits_the_configured_input_limit():
    """The check that has to hold for the defaults to be honest.

    The worst case is max_evidence forecast records *per metric* across four
    metrics, not max_evidence in total. Getting that wrong understates the
    prompt by fifteen records.
    """
    context = ContextSettings()
    llm = LLMSettings()
    forecast_worst_case = ForecastSettings().max_evidence * 4
    size = prompt_size(
        full_context(context.max_records, forecast_worst_case)
    )
    assert size < llm.max_input_chars, (
        f"a full context renders {size:,} characters against a "
        f"{llm.max_input_chars:,} limit; lower context.max_records or raise "
        "llm.num_ctx and llm.max_input_chars together"
    )


def test_the_input_limit_fits_the_context_window():
    """max_input_chars must be reachable, not merely configured.

    A limit larger than the window is accepted by this process and then
    silently truncated by the model, which then reasons on partial evidence.
    """
    llm = LLMSettings()
    available = (llm.num_ctx - llm.num_predict) * CHARS_PER_TOKEN
    assert llm.max_input_chars <= available


def test_mismatched_limits_are_rejected_at_configuration_time():
    """The shipped defaults were mismatched before this validator existed."""
    with pytest.raises(ValueError, match="exceeds what num_ctx"):
        LLMSettings(num_ctx=8192, max_input_chars=32000)


def test_one_record_costs_what_the_limits_assume():
    """Guards the estimate the configured limits are derived from.

    Note the arithmetic that has caught two people already: full_context(n)
    places n records in *each* of flows, dns and auth, so the difference
    between full_context(1) and full_context(0) is three records, not one.
    Reading it as one triples the apparent cost.
    """
    empty = prompt_size(full_context(0, 0))
    three = prompt_size(full_context(1, 0))
    per_record = (three - empty) / 3
    assert 300 < per_record < 600, (
        f"a flow record now costs {per_record:.0f} characters; the "
        "configured limits were derived from about 400 and need re-deriving"
    )


def test_one_forecast_record_costs_what_the_limits_assume():
    empty = prompt_size(full_context(0, 0))
    one = prompt_size(full_context(0, 1))
    assert 400 < one - empty < 800, (
        f"a forecast record now costs {one - empty} characters; the "
        "configured limits were derived from about 570"
    )


def test_raising_records_beyond_the_budget_is_caught():
    """The guard bites rather than merely existing."""
    oversized = prompt_size(full_context(120, 20))
    assert oversized > LLMSettings().max_input_chars
