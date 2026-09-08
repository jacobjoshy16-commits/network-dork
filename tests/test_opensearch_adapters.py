import json
from datetime import datetime, timezone
import sqlite3

import httpx
import pytest

from network_dork.adapters.context.opensearch import OpenSearchContextProvider
from network_dork.adapters.opensearch_security import (
    OpenSearchSecurityBootstrapper,
    SecurityBootstrapConfig,
    verify_read_credential_cannot_write,
)
from network_dork.adapters.sinks.opensearch import (
    OpenSearchOutcomeConflictError,
    OpenSearchReportSink,
)
from network_dork.adapters.alerts.file import FileAlertSource
from network_dork.audit import JsonlAuditLog
from network_dork.models import InvestigationReport


class RecordingAudit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


def first_alert():
    return next(iter(FileAlertSource("fixtures/alerts/alerts.jsonl").poll()))


def test_opensearch_context_provider_gathers_hits_and_prior_count():
    alert = first_alert()
    audit = RecordingAudit()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/network-flows-*/_search":
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "hits": [
                            {
                                "_id": "flow-1",
                                "_source": {
                                    "@timestamp": "2025-01-15T11:55:00Z",
                                    "source": {"ip": "10.77.0.1"},
                                    "destination": {"ip": "192.0.2.1"},
                                    "network": {"transport": "tcp"},
                                },
                            }
                        ]
                    }
                },
            )
        if request.url.path == "/dns-*/_search":
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "hits": [
                            {
                                "_id": "dns-1",
                                "_source": {
                                    "@timestamp": "2025-01-15T11:40:00Z",
                                    "source": {"ip": "10.77.0.1"},
                                    "dns": {"question": {"name": "callback-one.test"}},
                                },
                            }
                        ]
                    }
                },
            )
        if request.url.path == "/auth-*/_search":
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "hits": [
                            {
                                "_id": "auth-1",
                                "_source": {
                                    "@timestamp": "2025-01-15T11:35:00Z",
                                    "host": {"name": "workstation-01.test"},
                                    "source": {"ip": "10.77.0.1"},
                                    "event": {"outcome": "success"},
                                },
                            }
                        ]
                    }
                },
            )
        if request.url.path == "/security-alerts-*/_count":
            return httpx.Response(200, json={"count": 2})
        raise AssertionError(request.url.path)

    provider = OpenSearchContextProvider(
        base_url="http://127.0.0.1:9200",
        flows_index="network-flows-*",
        dns_index="dns-*",
        auth_index="auth-*",
        prior_alerts_index="security-alerts-*",
        username="reader",
        password="secret",
        audit=audit,
        transport=httpx.MockTransport(handler),
    )
    try:
        context = provider.gather(alert)
    finally:
        provider.close()
    assert len(context.flows) == 1
    assert len(context.dns) == 1
    assert len(context.auth) == 1
    assert context.prior_alert_count == 2
    assert context.unavailable == {}
    assert len(audit.events) == 8


def test_opensearch_context_provider_marks_missing_index_unavailable():
    alert = first_alert()
    audit = RecordingAudit()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/network-flows-*/_search":
            return httpx.Response(404, json={"error": "index_not_found_exception"})
        if request.url.path == "/dns-*/_search":
            return httpx.Response(200, json={"hits": {"hits": []}})
        if request.url.path == "/auth-*/_search":
            return httpx.Response(200, json={"hits": {"hits": []}})
        if request.url.path == "/security-alerts-*/_count":
            return httpx.Response(404, json={"error": "index_not_found_exception"})
        raise AssertionError(request.url.path)

    provider = OpenSearchContextProvider(
        base_url="http://127.0.0.1:9200",
        flows_index="network-flows-*",
        dns_index="dns-*",
        auth_index="auth-*",
        prior_alerts_index="security-alerts-*",
        username="reader",
        password="secret",
        audit=audit,
        transport=httpx.MockTransport(handler),
    )
    try:
        context = provider.gather(alert)
    finally:
        provider.close()
    assert context.flows == []
    assert context.prior_alert_count is None
    assert set(context.unavailable) == {"flows", "prior_alerts"}


def report() -> InvestigationReport:
    return InvestigationReport(
        alert_id="os-report-1",
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        summary="Evidence is insufficient for a strong conclusion.",
        mitre_technique=None,
        nist_control=None,
        confidence="low",
        context_used=["alert:os-report-1"],
        suggested_next_step="A human analyst should review the source evidence.",
        model_version="fake:test-only",
    )


def test_opensearch_sink_round_trip_and_conflict(tmp_path):
    state = {"doc": None}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if state["doc"] is None:
                return httpx.Response(404, json={"found": False})
            return httpx.Response(200, json={"_source": state["doc"]})
        if request.method == "PUT":
            state["doc"] = json.loads(request.content)
            return httpx.Response(201, json={"result": "created"})
        raise AssertionError(request.method)

    sink = OpenSearchReportSink(
        base_url="http://127.0.0.1:9200",
        index="network-dork-reports",
        username="writer",
        password="secret",
        audit=JsonlAuditLog(tmp_path / "audit.jsonl"),
        transport=httpx.MockTransport(handler),
    )
    original = report()
    try:
        sink.write("synthetic", original)
        sink.write("synthetic", original)
        assert sink.get_outcome("synthetic", original.alert_id) == original
        with pytest.raises(OpenSearchOutcomeConflictError):
            sink.write(
                "synthetic",
                original.model_copy(update={"summary": "different"}),
            )
    finally:
        sink.close()


def test_bootstrap_and_read_only_probe_issue_expected_requests():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.url.path == "/network-dork-reports/_doc/network-dork-read-only-probe":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json={"status": "OK"})

    bootstrapper = OpenSearchSecurityBootstrapper(
        base_url="http://127.0.0.1:9200",
        admin_username="admin",
        admin_password="admin-secret",
        transport=httpx.MockTransport(handler),
    )
    try:
        bootstrapper.bootstrap(
            SecurityBootstrapConfig(
                telemetry_user="nd-reader",
                telemetry_password="reader-secret",
                report_user="nd-writer",
                report_password="writer-secret",
                telemetry_indexes=["security-alerts-*", "network-flows-*", "dns-*", "auth-*"],
                report_index="network-dork-reports",
            )
        )
    finally:
        bootstrapper.close()
    verify_read_credential_cannot_write(
        base_url="http://127.0.0.1:9200",
        report_index="network-dork-reports",
        username="nd-reader",
        password="reader-secret",
        transport=httpx.MockTransport(handler),
    )
    assert requests[:2] == [
        ("PUT", "/_plugins/_security/api/roles/network_dork_telemetry_reader"),
        ("PUT", "/_plugins/_security/api/roles/network_dork_report_writer"),
    ]
    assert requests[-1] == (
        "PUT",
        "/network-dork-reports/_doc/network-dork-read-only-probe",
    )


def test_read_only_probe_fails_if_write_succeeds():
    with pytest.raises(PermissionError):
        verify_read_credential_cannot_write(
            base_url="http://127.0.0.1:9200",
            report_index="network-dork-reports",
            username="nd-reader",
            password="reader-secret",
            transport=httpx.MockTransport(lambda request: httpx.Response(201, json={"result": "created"})),
        )
