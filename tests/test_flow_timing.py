"""Timing statistics derived from supplied flows.

The last test is the important one, and it is a finding about the fixture
corpus rather than about this module.
"""

from datetime import datetime, timedelta, timezone

from network_dork.adapters.alerts.file import FileAlertSource
from network_dork.adapters.context.zeek_logs import ZeekLogsContextProvider
from network_dork.audit import JsonlAuditLog
from network_dork.flow_timing import observations, prompt_payload
from network_dork.models import Alert, AlertContext, EvidenceRecord

NOW = datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc)


def flow(offset_seconds: float, *, sent: int = 160, source: str = "10.0.0.1"):
    return EvidenceRecord(
        evidence_id=f"flows:conn.log:{offset_seconds}",
        kind="flows",
        source="conn.log",
        timestamp=NOW - timedelta(seconds=3600 - offset_seconds),
        fields={
            "id.orig_h": source,
            "id.resp_h": "203.0.113.5",
            "orig_bytes": sent,
        },
    )


def context(flows: list[EvidenceRecord]) -> AlertContext:
    return AlertContext(
        alert=Alert(
            source="test",
            alert_id="syn-001",
            timestamp=NOW,
            title="Alert",
            description="",
            src_ip="10.0.0.1",
            dst_ip=None,
            host=None,
            domains=[],
            original={},
        ),
        window_start=NOW - timedelta(hours=2),
        window_end=NOW,
        flows=flows,
        dns=[],
        auth=[],
        prior_alert_count=0,
        unavailable={},
    )


def test_a_fixed_interval_with_a_fixed_payload_is_reported_as_such():
    result = observations(context([flow(0), flow(300), flow(600)]))

    assert len(result) == 1
    identifier, fields = result[0]
    assert identifier == "timing:10.0.0.1->203.0.113.5"
    assert fields["mean_interval_seconds"] == 300.0
    assert fields["identical_intervals"] is True
    assert fields["identical_bytes_sent"] is True
    assert fields["interval_regularity"] == 100.0


def test_bursty_traffic_scores_low_regularity():
    bursty = context([flow(0), flow(5), flow(900)])
    _, fields = observations(bursty)[0]

    assert fields["identical_intervals"] is False
    assert fields["interval_regularity"] < 2.0


def test_two_connections_are_not_a_pattern():
    """One interval has no variance, so it says nothing about rhythm."""
    assert observations(context([flow(0), flow(300)])) == []


def test_varying_payloads_are_reported_as_varying():
    varied = context([flow(0, sent=160), flow(300, sent=9000), flow(600, sent=40)])
    _, fields = observations(varied)[0]

    assert fields["distinct_bytes_sent"] == 3
    assert fields["identical_bytes_sent"] is False


def test_pairs_are_kept_separate():
    mixed = context(
        [flow(0), flow(300), flow(600)]
        + [flow(0, source="10.0.0.9"), flow(60, source="10.0.0.9")]
    )
    assert [identifier for identifier, _ in observations(mixed)] == [
        "timing:10.0.0.1->203.0.113.5"
    ]


def test_flows_naming_no_addresses_are_skipped_not_fatal():
    anonymous = EvidenceRecord(
        evidence_id="flows:conn.log:x",
        kind="flows",
        source="conn.log",
        timestamp=NOW - timedelta(seconds=60),
        fields={"note": "no addresses here"},
    )
    assert observations(context([anonymous])) == []


# --- the finding -----------------------------------------------------------


def test_the_fixture_corpus_cannot_distinguish_beaconing_from_benign(tmp_path):
    """syn-001 is labelled c2_beaconing and syn-010 benign, and their flow
    evidence is structurally identical: same duration, same byte and packet
    counts, same conn_state, same 300-second spacing. Only the addresses,
    ports and the wording of the alert title differ.

    So no timing statistic can separate them, and neither can a larger
    language model. The labels in fixtures/ground_truth.yaml are not
    derivable from the telemetry the corpus supplies, which means
    `eval-reports` cannot measure whether a model reads evidence well -- it
    can only measure whether a model pattern-matches on alert titles, which
    is the behaviour the `evidence` metric exists to penalise.

    This test passes while that defect stands. Fixing the corpus should
    break it.
    """
    provider = ZeekLogsContextProvider(
        directory="fixtures/zeek",
        prior_alerts_path="fixtures/alerts/alerts.jsonl",
        window_days=7,
        max_records=30,
        audit=JsonlAuditLog(tmp_path / "audit.jsonl"),
    )
    alerts = {
        alert.alert_id: alert
        for alert in FileAlertSource(path="fixtures/alerts/alerts.jsonl").poll()
    }

    def timing(alert_id: str) -> dict:
        payload = prompt_payload(provider.gather(alerts[alert_id]))
        assert len(payload) == 1, alert_id
        return {
            key: value
            for key, value in payload[0].items()
            if key != "observation_id"
        }

    assert timing("syn-001") == timing("syn-010")
