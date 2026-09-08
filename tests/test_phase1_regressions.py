"""Regressions for the three defects found in the phase-7 audit.

1. Alert identifiers reached OpenSearch URLs unencoded, letting untrusted
   sensor data redirect a write to an arbitrary endpoint.
2. Outcomes were keyed on alert_id while leases were keyed on
   (source, alert_id), so a reused native id closed one alert with another
   alert's report.
3. A context-provider exception aborted the whole batch and stranded a lease.
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from network_dork.adapters.context.null import NullContextProvider
from network_dork.adapters.identity import normalize_alert_id
from network_dork.adapters.llm.fake import FakeLLMClient
from network_dork.adapters.sinks.opensearch import OpenSearchReportSink
from network_dork.adapters.sinks.sqlite import (
    OutcomeSchemaError,
    SQLiteReportSink,
)
from network_dork.audit import JsonlAuditLog
from network_dork.models import Alert, FailureRecord, InvestigationReport
from network_dork.pipeline import InvestigationPipeline, OutcomeIntegrityError
from network_dork.prompts import InvestigationPrompt
from network_dork.state import SQLiteState

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def alert(source: str = "synthetic", alert_id: str = "syn-001") -> Alert:
    return Alert(
        source=source,
        alert_id=alert_id,
        timestamp=NOW,
        title="Existing sensor alert",
        description="",
        src_ip="10.77.0.1",
        dst_ip=None,
        host=None,
        domains=[],
        original={},
    )


def report(alert_id: str = "syn-001") -> InvestigationReport:
    return InvestigationReport(
        alert_id=alert_id,
        timestamp=NOW,
        summary="Evidence is insufficient to characterize this alert.",
        mitre_technique=None,
        nist_control=None,
        confidence="low",
        context_used=[],
        suggested_next_step="An analyst should review the original alert.",
        model_version="fake:test-only",
    )


def build(tmp_path, source_alerts, llm=None, context=None):
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    sink = SQLiteReportSink(tmp_path / "reports.sqlite3", audit)
    state = SQLiteState(tmp_path / "state.sqlite3")

    class Source:
        def poll(self):
            return list(source_alerts)

    pipeline = InvestigationPipeline(
        source=Source(),
        context=context or NullContextProvider(),
        llm=llm or FakeLLMClient(),
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=state,
        prompts=InvestigationPrompt("fake:test-only"),
        model_version="fake:test-only",
        clock=lambda: NOW,
    )
    return pipeline, sink, state


# --- 1. identifier handling -------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "x/../../../_cluster/settings",
        "zeek-notice:C4J4Th/../../../../_cluster/settings",
        "id?refresh=wait_for&pretty",
        "id#fragment",
        "id with spaces",
        "%2e%2e/escaped",
    ],
)
def test_hostile_native_ids_normalize_into_one_safe_path_segment(hostile):
    normalized = normalize_alert_id("zeek-notice", hostile)
    Alert.model_validate(
        {
            **alert().model_dump(mode="json"),
            "source": "zeek-notice",
            "alert_id": normalized,
        }
    )
    assert "/" not in normalized
    assert "?" not in normalized
    assert "#" not in normalized
    assert " " not in normalized


def test_distinct_native_ids_never_collapse_onto_one_alert_id():
    first = normalize_alert_id("zeek-notice", "abc/def")
    second = normalize_alert_id("zeek-notice", "abc?def")
    assert first != second


def test_unremarkable_native_ids_are_left_readable():
    assert normalize_alert_id("suricata-eve", "12345:2001219:7") == (
        "suricata-eve:12345:2001219:7"
    )


def test_alert_id_cannot_move_the_opensearch_request_path(tmp_path):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.method == "PUT":
            return httpx.Response(201, json={"result": "created"})
        return httpx.Response(404, json={"found": False})

    sink = OpenSearchReportSink(
        base_url="http://127.0.0.1:9200",
        index="network-dork-reports",
        username="writer",
        password="secret",
        audit=JsonlAuditLog(tmp_path / "audit.jsonl"),
        transport=httpx.MockTransport(handler),
    )
    try:
        # A normalized id can still contain ":" and "."; both must be encoded
        # rather than left to interact with the path.
        sink.write("zeek-notice", report(alert_id="zeek-notice:C4J4Th.deadbeef"))
    finally:
        sink.close()

    assert seen
    for url in seen:
        assert url.startswith("http://127.0.0.1:9200/network-dork-reports/_doc/")
        assert "_cluster" not in url
        assert url.count("/") == 5


# --- 2. outcome keyspace ----------------------------------------------------


def test_two_sources_reusing_a_native_id_get_separate_investigations(tmp_path):
    alerts = [alert(source="suricata", alert_id="1234"),
              alert(source="zeek-notice", alert_id="1234")]
    llm = FakeLLMClient()
    pipeline, sink, state = build(tmp_path, alerts, llm=llm)

    results = pipeline.run_once()

    assert len(llm.calls) == 2, "second alert must be investigated, not reused"
    assert len(results) == 2
    assert state.inspect("suricata", "1234")["status"] == "succeeded"
    assert state.inspect("zeek-notice", "1234")["status"] == "succeeded"
    assert sink.get_outcome("suricata", "1234") is not None
    assert sink.get_outcome("zeek-notice", "1234") is not None


def test_recovery_refuses_an_outcome_belonging_to_another_alert(tmp_path):
    import sqlite3

    pipeline, sink, state = build(tmp_path, [alert()])
    foreign = report(alert_id="some-other-alert")
    # Simulate a corrupted store: the row under this key holds a foreign id.
    with sqlite3.connect(tmp_path / "reports.sqlite3") as connection:
        connection.execute(
            "INSERT INTO outcomes VALUES (?, ?, ?, ?, ?)",
            (
                "synthetic",
                "syn-001",
                "report",
                foreign.timestamp.isoformat(),
                foreign.model_dump_json(),
            ),
        )
    with pytest.raises(OutcomeIntegrityError):
        pipeline.run_once()


def test_legacy_outcomes_database_is_refused_not_silently_adopted(tmp_path):
    import sqlite3

    path = tmp_path / "reports.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("""
            CREATE TABLE outcomes (
                alert_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
    with pytest.raises(OutcomeSchemaError, match="migrate_outcomes"):
        SQLiteReportSink(path, JsonlAuditLog(tmp_path / "audit.jsonl"))


# --- 3. per-alert failure isolation -----------------------------------------


class BrokenContext:
    def gather(self, alert):
        raise RuntimeError("telemetry backend is unreachable")


def test_context_failure_is_recorded_and_the_batch_continues(tmp_path):
    alerts = [alert(alert_id="syn-001"), alert(alert_id="syn-002")]
    pipeline, sink, state = build(tmp_path, alerts, context=BrokenContext())

    results = pipeline.run_once()

    assert len(results) == 2, "a broken provider must not abort the batch"
    assert all(isinstance(result, FailureRecord) for result in results)
    assert {result.category for result in results} == {"context_error"}
    for identifier in ("syn-001", "syn-002"):
        assert state.inspect("synthetic", identifier)["status"] == "failed"
        assert isinstance(
            sink.get_outcome("synthetic", identifier), FailureRecord
        )


def test_context_failure_does_not_strand_the_lease(tmp_path):
    pipeline, sink, state = build(
        tmp_path, [alert()], context=BrokenContext()
    )
    pipeline.run_once()
    row = state.inspect("synthetic", "syn-001")
    assert row["status"] == "failed"
    assert row["lease_until"] == 0


def test_outcome_store_failure_aborts_rather_than_losing_work(tmp_path):
    class BrokenSink:
        def get_outcome(self, source, alert_id):
            return None

        def write(self, source, report):
            raise OSError("outcome store is unavailable")

        def write_failure(self, source, failure):
            raise OSError("outcome store is unavailable")

    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    state = SQLiteState(tmp_path / "state.sqlite3")
    broken = BrokenSink()

    class Source:
        def poll(self):
            return [alert(alert_id="syn-001"), alert(alert_id="syn-002")]

    pipeline = InvestigationPipeline(
        source=Source(),
        context=NullContextProvider(),
        llm=FakeLLMClient(),
        sink=broken,
        failures=broken,
        outcomes=broken,
        state=state,
        prompts=InvestigationPrompt("fake:test-only"),
        model_version="fake:test-only",
        clock=lambda: NOW,
    )
    with pytest.raises(OSError, match="outcome store is unavailable"):
        pipeline.run_once()
    # The second alert was never claimed, so a later run can still take it.
    assert state.inspect("synthetic", "syn-002") is None


def test_lost_lease_skips_the_alert_without_aborting_the_batch(tmp_path):
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    sink = SQLiteReportSink(tmp_path / "reports.sqlite3", audit)
    state = SQLiteState(tmp_path / "state.sqlite3")
    stolen = alert(alert_id="syn-001")
    healthy = alert(alert_id="syn-002")

    class StealingContext:
        """Expires the first alert's lease mid-investigation."""

        def __init__(self):
            self.calls = 0

        def gather(self, current):
            self.calls += 1
            if current.alert_id == stolen.alert_id:
                state.finish(
                    current.source,
                    current.alert_id,
                    state.inspect(current.source, current.alert_id)["owner"],
                    "failed",
                    NOW,
                )
            return NullContextProvider().gather(current)

    class Source:
        def poll(self):
            return [stolen, healthy]

    pipeline = InvestigationPipeline(
        source=Source(),
        context=StealingContext(),
        llm=FakeLLMClient(),
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=state,
        prompts=InvestigationPrompt("fake:test-only"),
        model_version="fake:test-only",
        clock=lambda: NOW,
    )
    results = pipeline.run_once()
    assert len(results) == 1
    assert results[0].alert_id == "syn-002"
