"""Phase 6: forecast evidence reaching a report and being checked there.

The enrichment tests prove forecast evidence is produced. These prove it is
usable: the model is offered it, may cite it, has it grounded like any other
evidence, and is told what it does not mean.
"""

from datetime import datetime, timedelta, timezone
import json

import pytest

from network_dork.adapters.sinks.sqlite import SQLiteReportSink
from network_dork.audit import JsonlAuditLog
from network_dork.grounding import check
from network_dork.models import (
    Alert,
    AlertContext,
    EvidenceRecord,
    FailureRecord,
    InvestigationReport,
)
from network_dork.pipeline import InvestigationPipeline
from network_dork.prompts import InvestigationPrompt
from network_dork.state import SQLiteState

NOW = datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc)
FORECAST_ID = "forecast:conn_regularity:2025-01-15T09:00:00+00:00"


def alert() -> Alert:
    return Alert(
        source="synthetic",
        alert_id="syn-001",
        timestamp=NOW,
        title="Periodic HTTP callback alert",
        description="Recurring outbound callbacks observed.",
        src_ip="10.77.0.1",
        dst_ip="192.0.2.1",
        host="workstation-01.test",
        domains=["callback-one.test"],
        original={},
    )


def forecast_record() -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=FORECAST_ID,
        kind="forecast",
        source="forecast:SeasonalNaiveForecaster:conn_regularity",
        timestamp=NOW - timedelta(hours=3),
        fields={
            "metric": "conn_regularity",
            "entity": "10.77.0.1",
            "bucket_seconds": 300,
            "observed": 49.02,
            "predicted": 4.57,
            "predicted_range": [2.85, 6.29],
            "deviation_score": 12.42,
            "direction": "above_forecast",
            "note": (
                "Statistical deviation from a predicted range. Not a "
                "detection and not evidence of malicious activity."
            ),
        },
    )


def context(with_forecast: bool = True) -> AlertContext:
    return AlertContext(
        alert=alert(),
        window_start=NOW - timedelta(days=7),
        window_end=NOW,
        flows=[
            EvidenceRecord(
                evidence_id="flows:conn.log:1",
                kind="flows",
                source="fixtures/zeek/conn.log:1",
                timestamp=NOW - timedelta(hours=4),
                fields={"id.orig_h": "10.77.0.1", "id.resp_h": "192.0.2.1"},
            )
        ],
        dns=[],
        auth=[],
        forecast=[forecast_record()] if with_forecast else [],
        prior_alert_count=2,
        unavailable={"dns": "dns file is unavailable"},
    )


# --- the model is offered forecast evidence ---------------------------------


def test_forecast_ids_are_offered_as_citable_context():
    _, user = InvestigationPrompt("m").render(context())
    payload = json.loads(user)
    assert FORECAST_ID in payload["allowed_context_ids"]


def test_forecast_fields_reach_the_model_with_their_caveat():
    _, user = InvestigationPrompt("m").render(context())
    supplied = json.loads(user)["supplied_context"]["forecast"][0]["fields"]
    assert supplied["observed"] == 49.02
    assert supplied["predicted_range"] == [2.85, 6.29]
    assert "not a detection" in supplied["note"].lower()


def test_the_prompt_tells_the_model_deviation_is_not_malice():
    system, _ = InvestigationPrompt("m").render(context())
    assert "not a detection and not proof of malice" in system
    assert "Never raise confidence on a" in system


def test_truncation_is_disclosed_to_the_model():
    truncated = context().model_copy(update={"truncated": {"flows": 4000}})
    system, user = InvestigationPrompt("m").render(truncated)
    assert json.loads(user)["supplied_context"]["truncated"]["flows"] == 4000
    assert "truncated evidence" in system


# --- citation and grounding -------------------------------------------------


def report(**overrides) -> InvestigationReport:
    base = {
        "alert_id": "syn-001",
        "timestamp": NOW,
        "summary": (
            "Connection regularity for 10.77.0.1 ran well above its predicted "
            "range in the hours before the alert, which is an observation "
            "about traffic rhythm rather than proof of intent. DNS telemetry "
            "was unavailable."
        ),
        "mitre_technique": "T1071.001",
        "nist_control": "SI-4",
        "confidence": "medium",
        "disposition": "suspicious",
        "context_used": ["alert:syn-001", "flows:conn.log:1", FORECAST_ID],
        "suggested_next_step": (
            "An analyst should review proxy logs for workstation-01.test."
        ),
        "model_version": "qwen2.5:3b-instruct",
    }
    base.update(overrides)
    return InvestigationReport.model_validate(base)


def test_a_report_citing_forecast_evidence_is_grounded():
    assert check(report(), context()) == []


def test_citing_a_forecast_id_that_was_not_supplied_is_rejected():
    """The pipeline's allow-list must cover forecast identifiers too."""
    fabricated = report(
        context_used=["alert:syn-001", "forecast:conn_count:2025-01-01T00:00:00+00:00"]
    )
    with pytest.raises(ValueError, match="unknown context identifier"):
        InvestigationPipeline._validate_response(
            fabricated.model_dump_json(),
            alert(),
            context(),
            "qwen2.5:3b-instruct",
            InvestigationPrompt(
                "qwen2.5:3b-instruct", clock=lambda: NOW
            ).render(context())[1],
        )


def test_a_mistranscribed_timestamp_does_not_lose_the_report():
    """Observed with qwen2.5:3b-instruct: every field right but the
    microseconds, which the application owns anyway."""
    prompt = InvestigationPrompt(
        "qwen2.5:3b-instruct", clock=lambda: NOW
    ).render(context())[1]
    sloppy = report(timestamp=NOW.replace(microsecond=405000))

    validated = InvestigationPipeline._validate_response(
        sloppy.model_dump_json(),
        alert(),
        context(),
        "qwen2.5:3b-instruct",
        prompt,
    )

    assert validated.timestamp == NOW
    assert validated.summary == sloppy.summary


def test_entities_named_only_in_forecast_evidence_count_as_grounded():
    """Forecast records carry the entity; naming it is not fabrication."""
    grounded = report(
        summary="Traffic from 10.77.0.1 departed from its predicted range."
    )
    assert check(grounded, context()) == []


def test_claiming_the_forecast_detected_something_is_still_an_action_claim():
    ungrounded = report(
        summary="The host was quarantined after the forecast flagged it."
    )
    violations = check(ungrounded, context())
    assert any("cannot act" in violation for violation in violations)


# --- end to end -------------------------------------------------------------


def test_a_full_run_persists_a_report_citing_forecast_evidence(tmp_path):
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    sink = SQLiteReportSink(tmp_path / "reports.sqlite3", audit)
    state = SQLiteState(tmp_path / "state.sqlite3")
    prompts = InvestigationPrompt("qwen2.5:3b-instruct", clock=lambda: NOW)

    class Source:
        def poll(self):
            return [alert()]

    class Context:
        def gather(self, _alert):
            return context()

    class Model:
        """Stands in for Qwen citing the forecast evidence it was given."""

        def complete(self, system, user):
            identity = json.loads(user)["required_identity"]
            payload = report().model_dump(mode="json")
            payload.update(identity)
            return json.dumps(payload)

    pipeline = InvestigationPipeline(
        source=Source(),
        context=Context(),
        llm=Model(),
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=state,
        prompts=prompts,
        model_version="qwen2.5:3b-instruct",
        audit=audit,
        grounding=check,
        clock=lambda: NOW,
    )
    results = pipeline.run_once()

    assert len(results) == 1
    stored = results[0]
    assert isinstance(stored, InvestigationReport), getattr(
        stored, "errors", None
    )
    assert FORECAST_ID in stored.context_used
    assert sink.get_outcome("synthetic", "syn-001") == stored


def test_a_run_without_forecast_evidence_is_unaffected(tmp_path):
    """Enrichment is additive: turning it off changes nothing else."""
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    sink = SQLiteReportSink(tmp_path / "reports.sqlite3", audit)
    state = SQLiteState(tmp_path / "state.sqlite3")

    class Source:
        def poll(self):
            return [alert()]

    class Context:
        def gather(self, _alert):
            return context(with_forecast=False)

    class Model:
        def complete(self, system, user):
            identity = json.loads(user)["required_identity"]
            payload = report(
                context_used=["alert:syn-001", "flows:conn.log:1"],
                summary=(
                    "Repeated outbound connections from 10.77.0.1 to "
                    "192.0.2.1. DNS telemetry was unavailable."
                ),
            ).model_dump(mode="json")
            payload.update(identity)
            return json.dumps(payload)

    pipeline = InvestigationPipeline(
        source=Source(),
        context=Context(),
        llm=Model(),
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=state,
        prompts=InvestigationPrompt("qwen2.5:3b-instruct", clock=lambda: NOW),
        model_version="qwen2.5:3b-instruct",
        audit=audit,
        grounding=check,
        clock=lambda: NOW,
    )
    results = pipeline.run_once()
    assert isinstance(results[0], InvestigationReport)
    assert not any(
        item.startswith("forecast:") for item in results[0].context_used
    )


def test_the_audit_records_which_instructions_produced_the_report(tmp_path):
    """A report is only reproducible if the prompt is identified too."""
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    sink = SQLiteReportSink(tmp_path / "reports.sqlite3", audit)
    state = SQLiteState(tmp_path / "state.sqlite3")

    class Source:
        def poll(self):
            return [alert()]

    class Context:
        def gather(self, _alert):
            return context()

    class Model:
        def complete(self, system, user):
            identity = json.loads(user)["required_identity"]
            payload = report().model_dump(mode="json")
            payload.update(identity)
            return json.dumps(payload)

    InvestigationPipeline(
        source=Source(),
        context=Context(),
        llm=Model(),
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=state,
        prompts=InvestigationPrompt("qwen2.5:3b-instruct", clock=lambda: NOW),
        model_version="qwen2.5:3b-instruct",
        audit=audit,
        grounding=check,
        system_prompt_digest="deadbeef",
        clock=lambda: NOW,
    ).run_once()

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]
    responses = [e for e in events if e["action"] == "llm_response"]
    assert responses
    assert responses[0]["parameters"]["system_prompt_sha256"] == "deadbeef"
