import json
from datetime import timedelta
import shutil

import pytest

from network_dork.adapters.alerts.file import FileAlertSource
from network_dork.adapters.context.zeek_logs import ZeekLogsContextProvider
from network_dork.audit import JsonlAuditLog

def corpus():
    return list(FileAlertSource("fixtures/alerts/alerts.jsonl").poll())

def provider(tmp_path, directory="fixtures/zeek", alerts=None):
    return ZeekLogsContextProvider(
        directory=directory,
        prior_alerts_path=alerts or "fixtures/alerts/alerts.jsonl",
        audit=JsonlAuditLog(tmp_path / "audit.jsonl"),
    )

@pytest.mark.parametrize("index", [0, 3, 7])
def test_exact_flows_dns_and_auth_for_three_fixtures(tmp_path, index):
    alert = corpus()[index]
    number = index + 1
    context = provider(tmp_path).gather(alert)

    assert [row.fields["uid"] for row in context.flows] == [
        f"C{number:02d}{offset}" for offset in range(3)
    ]
    assert [row.fields["uid"] for row in context.dns] == [f"D{number:02d}"]
    assert context.dns[0].fields["query"] == alert.domains[0]
    assert len(context.auth) == 1
    assert context.auth[0].fields["host"] == alert.host
    assert context.auth[0].fields["user"] == f"synthetic-user-{number:02d}"
    assert context.prior_alert_count == 0
    assert context.unavailable == {}

def test_each_context_query_has_audited_attempt_and_completion(tmp_path):
    provider(tmp_path).gather(corpus()[0])
    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
    ]
    assert len(events) == 8
    operations = {}
    for event in events:
        assert event["action"] == "context_query"
        assert event["alert_id"] == "syn-001"
        assert event["timestamp"]
        assert event["parameters"]["filters"]
        operations.setdefault(event["operation_id"], []).append(event)
    assert len(operations) == 4
    for pair in operations.values():
        assert [event["stage"] for event in pair] == ["attempt", "success"]

def test_missing_context_is_explicit_not_an_error(tmp_path):
    context = provider(
        tmp_path,
        directory=tmp_path / "missing",
        alerts=tmp_path / "missing-alerts.jsonl",
    ).gather(corpus()[0])
    assert context.flows == []
    assert context.dns == []
    assert context.auth == []
    assert context.prior_alert_count is None
    assert set(context.unavailable) == {
        "flows", "dns", "auth", "prior_alerts"
    }

def test_outside_window_and_future_records_are_excluded(tmp_path):
    directory = tmp_path / "zeek"
    shutil.copytree("fixtures/zeek", directory)
    alert = corpus()[0]
    connection = json.loads(
        (directory / "conn.log").read_text().splitlines()[0]
    )
    with (directory / "conn.log").open("a") as stream:
        for uid, when in (
            ("Cold", alert.timestamp - timedelta(days=8)),
            ("Cfuture", alert.timestamp + timedelta(seconds=1)),
        ):
            row = {**connection, "uid": uid, "ts": when.timestamp()}
            stream.write(json.dumps(row) + "\n")
    context = provider(tmp_path, directory).gather(alert)
    assert len(context.flows) == 3

def test_corrupt_file_does_not_return_silent_partial_context(tmp_path):
    directory = tmp_path / "zeek"
    shutil.copytree("fixtures/zeek", directory)
    with (directory / "conn.log").open("a") as stream:
        stream.write("{broken json\n")
    context = provider(tmp_path, directory).gather(corpus()[0])
    assert context.flows == []
    assert "flows" in context.unavailable
    assert len(context.dns) == 1

def test_prior_alert_count_excludes_self_future_and_duplicates(tmp_path):
    alert = corpus()[0]
    previous = alert.model_copy(
        update={
            "alert_id": "previous",
            "timestamp": alert.timestamp - timedelta(hours=1),
        }
    )
    future = alert.model_copy(
        update={
            "alert_id": "future",
            "timestamp": alert.timestamp + timedelta(hours=1),
        }
    )
    path = tmp_path / "alerts.jsonl"
    path.write_text(
        "\n".join(
            row.model_dump_json()
            for row in [alert, previous, previous, future]
        ) + "\n"
    )
    context = provider(tmp_path, alerts=path).gather(alert)
    assert context.prior_alert_count == 1

def test_query_does_not_start_when_audit_is_unavailable():
    class BrokenAudit:
        def record(self, event):
            raise OSError("audit unavailable")

    context = ZeekLogsContextProvider(
        directory="fixtures/zeek",
        prior_alerts_path="fixtures/alerts/alerts.jsonl",
        audit=BrokenAudit(),
    )
    with pytest.raises(OSError, match="audit unavailable"):
        context.gather(corpus()[0])


def test_prior_alerts_are_counted_from_a_non_jsonl_alert_source(tmp_path):
    """The count was read by parsing alerts.path as normalized Alert JSONL,
    so once every alert adapter honoured that setting, a Suricata eve.json
    raised ValidationError on line one and prior_alerts came back
    unavailable. The provider is given the configured AlertSource instead,
    which knows its own format."""
    from network_dork.adapters.alerts.suricata_eve import SuricataEveAlertSource
    from network_dork.adapters.context.zeek_logs import ZeekLogsContextProvider
    from network_dork.audit import JsonlAuditLog

    eve = tmp_path / "eve.json"
    eve.write_text(
        "\n".join(
            json.dumps(
                {
                    "event_type": "alert",
                    "flow_id": index,
                    "timestamp": stamp,
                    "src_ip": "10.77.0.1",
                    "dest_ip": "192.0.2.1",
                    "alert": {
                        "signature": f"ET INFO alert {index}",
                        "signature_id": 100 + index,
                        "category": "Misc",
                    },
                }
            )
            for index, stamp in enumerate(
                (
                    "2025-01-15T11:30:00+00:00",
                    "2025-01-15T11:45:00+00:00",
                    "2025-01-15T12:00:00+00:00",
                ),
                start=1,
            )
        )
        + "\n",
        encoding="utf-8",
    )
    source = SuricataEveAlertSource(path=eve)
    subject = [a for a in source.poll() if a.alert_id.endswith(":3")][0]

    provider = ZeekLogsContextProvider(
        directory="fixtures/zeek",
        prior_alerts_path=eve,
        audit=JsonlAuditLog(tmp_path / "audit.jsonl"),
        prior_alert_source=SuricataEveAlertSource(path=eve),
    )
    context = provider.gather(subject)

    assert context.prior_alert_count == 2
    assert "prior_alerts" not in context.unavailable


def test_prior_alerts_still_read_jsonl_when_given_no_source(tmp_path):
    """A provider constructed with only a path keeps working."""
    from network_dork.adapters.context.zeek_logs import ZeekLogsContextProvider
    from network_dork.audit import JsonlAuditLog

    provider = ZeekLogsContextProvider(
        directory="fixtures/zeek",
        prior_alerts_path="fixtures/alerts/alerts.jsonl",
        audit=JsonlAuditLog(tmp_path / "audit.jsonl"),
    )
    alerts = {
        alert.alert_id: alert
        for alert in FileAlertSource(path="fixtures/alerts/alerts.jsonl").poll()
    }
    context = provider.gather(alerts["syn-007"])

    assert context.prior_alert_count is not None
    assert "prior_alerts" not in context.unavailable
