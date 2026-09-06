from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import sqlite3

import pytest

from network_dork.adapters.sinks.sqlite import (
    OutcomeConflictError,
    SQLiteReportSink,
)
from network_dork.audit import JsonlAuditLog
from network_dork.models import AuditEvent, InvestigationReport

def report():
    return InvestigationReport(
        alert_id="audit-test",
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        summary="There is insufficient evidence for a conclusion.",
        mitre_technique=None,
        nist_control=None,
        confidence="low",
        context_used=["alert:audit-test"],
        suggested_next_step="An analyst should review the source evidence.",
        model_version="fake:test-only",
    )

def test_audit_appends_without_replacing_previous_bytes(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = JsonlAuditLog(path)
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc),
        alert_id="audit-test",
        operation_id="first",
        action="report_write",
        stage="attempt",
        parameters={"sink": "test"},
    )
    audit.record(event)
    prefix = path.read_bytes()
    audit.record(event.model_copy(update={"operation_id": "second"}))
    assert path.read_bytes().startswith(prefix)
    assert len(path.read_text().splitlines()) == 2

def test_concurrent_audit_records_remain_complete_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = JsonlAuditLog(path)

    def append(number):
        audit.record(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                alert_id="audit-test",
                operation_id=str(number),
                action="context_query",
                stage="attempt",
                parameters={"number": number},
            )
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(40)))
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert {event["operation_id"] for event in events} == {
        str(number) for number in range(40)
    }

def test_sink_is_idempotent_but_rejects_conflicting_report(tmp_path):
    sink = SQLiteReportSink(
        tmp_path / "reports.sqlite3",
        JsonlAuditLog(tmp_path / "audit.jsonl"),
    )
    original = report()
    sink.write(original)
    sink.write(original)
    with pytest.raises(OutcomeConflictError):
        sink.write(original.model_copy(update={"summary": "Different summary"}))
    assert sink.get_outcome(original.alert_id) == original

def test_audit_failure_before_write_prevents_persistence(tmp_path):
    class BrokenAudit:
        def record(self, event):
            raise OSError("audit unavailable")

    path = tmp_path / "reports.sqlite3"
    sink = SQLiteReportSink(path, BrokenAudit())
    with pytest.raises(OSError, match="audit unavailable"):
        sink.write(report())
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM outcomes"
        ).fetchone()[0] == 0

def test_completion_audit_failure_leaves_canonical_outcome_for_recovery(tmp_path):
    class FailCompletionAudit:
        def record(self, event):
            if event.stage == "success":
                raise OSError("completion audit unavailable")

    path = tmp_path / "reports.sqlite3"
    sink = SQLiteReportSink(path, FailCompletionAudit())
    original = report()
    with pytest.raises(OSError, match="completion audit unavailable"):
        sink.write(original)
    assert sink.get_outcome(original.alert_id) == original

    recovered = SQLiteReportSink(
        path, JsonlAuditLog(tmp_path / "recovered-audit.jsonl")
    )
    recovered.write(original)
    assert recovered.get_outcome(original.alert_id) == original
