import ast
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest

from network_dork.adapters.alerts.file import FileAlertSource
from network_dork.adapters.context.zeek_logs import ZeekLogsContextProvider
from network_dork.adapters.llm.fake import FakeLLMClient
from network_dork.adapters.sinks.sqlite import SQLiteReportSink
from network_dork.audit import JsonlAuditLog
from network_dork.models import FailureRecord, InvestigationReport
from network_dork.pipeline import InvestigationPipeline
from network_dork.prompts import InvestigationPrompt
from network_dork.state import SQLiteState

NOW = datetime(2025, 1, 16, tzinfo=timezone.utc)

class SingleSource:
    def __init__(self, alert):
        self.alert = alert

    def poll(self):
        return [self.alert]

def build(tmp_path, responses=None, audit=None):
    alert = next(iter(FileAlertSource("fixtures/alerts/alerts.jsonl").poll()))
    audit = audit or JsonlAuditLog(tmp_path / "audit.jsonl")
    sink = SQLiteReportSink(tmp_path / "reports.sqlite3", audit)
    state = SQLiteState(tmp_path / "state.sqlite3")
    llm = FakeLLMClient(responses)
    pipeline = InvestigationPipeline(
        source=SingleSource(alert),
        context=ZeekLogsContextProvider(
            "fixtures/zeek",
            "fixtures/alerts/alerts.jsonl",
            audit,
        ),
        llm=llm,
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=state,
        prompts=InvestigationPrompt("fake:test-only", clock=lambda: NOW),
        model_version="fake:test-only",
        max_attempts=3,
        clock=lambda: NOW,
    )
    return pipeline, llm, sink, state, alert

def valid_response():
    return json.dumps({
        "alert_id": "syn-001",
        "timestamp": NOW.isoformat(),
        "summary": "Available evidence does not establish malicious intent.",
        "mitre_technique": None,
        "nist_control": None,
        "confidence": "low",
        "context_used": ["alert:syn-001", "flows:conn.log:1"],
        "suggested_next_step": "An analyst should review the existing alert.",
        "model_version": "fake:test-only",
    })

def test_happy_path_persists_report_and_audits_every_operation(tmp_path):
    pipeline, llm, sink, state, alert = build(
        tmp_path, [valid_response()]
    )
    results = pipeline.run_once()
    assert len(results) == 1
    assert isinstance(results[0], InvestigationReport)
    assert sink.get_outcome(alert.source, alert.alert_id) == results[0]
    assert len(llm.calls) == 1
    assert state.inspect(alert.source, alert.alert_id)["status"] == "succeeded"

    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        assert connection.execute(
            "SELECT count(*) FROM reports"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT count(*) FROM failures"
        ).fetchone()[0] == 0

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]
    assert len(events) == 10
    successes = [e for e in events if e["stage"] == "success"]
    assert sum(e["action"] == "context_query" for e in successes) == 4
    assert sum(e["action"] == "report_write" for e in successes) == 1
    for event in events:
        assert event["timestamp"]
        assert event["alert_id"] == alert.alert_id
        assert event["parameters"]

@pytest.mark.parametrize(
    "bad",
    [
        "not JSON",
        "{}",
        '{"summary": "partial report"}',
        '```json\n{}\n```',
    ],
)
def test_bounded_invalid_output_persists_only_explicit_failure(tmp_path, bad):
    pipeline, llm, sink, state, alert = build(tmp_path, [bad, bad, bad])
    results = pipeline.run_once()
    assert len(results) == 1
    assert isinstance(results[0], FailureRecord)
    assert results[0].category == "invalid_model_output"
    assert results[0].attempts == 3
    assert len(results[0].errors) == 3
    assert len(llm.calls) == 3
    assert state.inspect(alert.source, alert.alert_id)["status"] == "failed"
    assert isinstance(
        sink.get_outcome(alert.source, alert.alert_id), FailureRecord
    )
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        assert connection.execute(
            "SELECT count(*) FROM reports"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM failures"
        ).fetchone()[0] == 1

def test_retry_can_recover_without_filling_fields(tmp_path):
    pipeline, llm, sink, state, alert = build(
        tmp_path, ["{malformed", "{}", valid_response()]
    )
    result = pipeline.run_once()[0]
    assert isinstance(result, InvestigationReport)
    assert len(llm.calls) == 3
    assert result == InvestigationReport.model_validate_json(valid_response())

@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("alert_id", "different-alert"),
        ("model_version", "fabricated-model"),
        ("timestamp", "2024-01-01T00:00:00+00:00"),
        ("context_used", ["flows:nonexistent:999"]),
    ],
)
def test_semantically_invalid_output_is_not_persisted_as_report(
    tmp_path, field, value
):
    value_dict = json.loads(valid_response())
    value_dict[field] = value
    bad = json.dumps(value_dict)
    pipeline, *_ = build(tmp_path, [bad, bad, bad])
    assert isinstance(pipeline.run_once()[0], FailureRecord)

def test_llm_unavailability_has_explicit_failure_record(tmp_path):
    pipeline, llm, *_ = build(
        tmp_path,
        [TimeoutError("secret"), TimeoutError("secret"), TimeoutError("secret")],
    )
    result = pipeline.run_once()[0]
    assert isinstance(result, FailureRecord)
    assert result.category == "llm_unavailable"
    assert "secret" not in result.model_dump_json()
    assert len(llm.calls) == 3

def test_restart_skips_terminal_alert(tmp_path):
    first, *_ = build(tmp_path, [valid_response()])
    assert len(first.run_once()) == 1
    restarted, llm, *_ = build(tmp_path, [])
    assert restarted.run_once() == []
    assert llm.calls == []

def test_recovery_after_sink_commit_before_state_finish(tmp_path):
    pipeline, llm, sink, state, alert = build(tmp_path, [])
    existing = InvestigationReport.model_validate_json(valid_response())
    sink.write(alert.source, existing)

    assert state.claim(
        alert.source,
        alert.alert_id,
        "crashed-worker",
        NOW - timedelta(hours=1),
        10,
    )
    result = pipeline.run_once()
    assert result == [existing]
    assert llm.calls == []
    assert state.inspect(alert.source, alert.alert_id)["status"] == "succeeded"
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        assert connection.execute(
            "SELECT count(*) FROM reports"
        ).fetchone()[0] == 1

def test_pipeline_imports_only_stdlib_and_interfaces():
    tree = ast.parse(Path("src/network_dork/pipeline.py").read_text())
    internal_imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("network_dork"):
                internal_imports.append(node.module)
        elif isinstance(node, ast.Import):
            internal_imports.extend(
                alias.name for alias in node.names
                if alias.name.startswith("network_dork")
            )
    assert internal_imports == ["network_dork.interfaces"]
