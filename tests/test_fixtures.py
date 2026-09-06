import json
from datetime import datetime
from pathlib import Path

import yaml

from network_dork.adapters.alerts.file import FileAlertSource

def rows(filename):
    return [
        json.loads(line)
        for line in Path("fixtures/zeek", filename).read_text().splitlines()
        if line.strip()
    ]

def test_corpus_coverage_and_label_separation():
    alerts = list(FileAlertSource("fixtures/alerts/alerts.jsonl").poll())
    truth = yaml.safe_load(Path("fixtures/ground_truth.yaml").read_text())
    labels = truth["alerts"]
    assert len(alerts) == len(labels) == 12
    assert len({alert.alert_id for alert in alerts}) == 12
    assert {alert.alert_id for alert in alerts} == set(labels)
    assert {label["category"] for label in labels.values()} >= {
        "c2_beaconing",
        "dns_tunneling",
        "data_exfiltration",
        "lateral_movement",
        "benign",
    }
    assert sum(label["benign"] for label in labels.values()) >= 3
    for alert in alerts:
        serialized = alert.model_dump_json()
        assert "mitre_technique" not in serialized
        assert "nist_control" not in serialized
        assert "ground_truth" not in serialized
        assert labels[alert.alert_id]["origin"] == "synthetic"

def test_every_alert_has_matching_connection_dns_and_auth_evidence():
    alerts = list(FileAlertSource("fixtures/alerts/alerts.jsonl").poll())
    connections = rows("conn.log")
    dns = rows("dns.log")
    auth = rows("auth.log")
    for alert in alerts:
        src = str(alert.src_ip)
        dst = str(alert.dst_ip)
        matching_flows = [
            row for row in connections
            if row["id.orig_h"] == src and row["id.resp_h"] == dst
        ]
        matching_dns = [
            row for row in dns
            if row["id.orig_h"] == src and row["query"] in alert.domains
        ]
        matching_auth = [row for row in auth if row["host"] == alert.host]
        assert len(matching_flows) == 3
        assert len(matching_dns) == 1
        assert len(matching_auth) == 1
        for row in matching_flows + matching_dns + matching_auth:
            timestamp = datetime.fromtimestamp(
                row["ts"], tz=alert.timestamp.tzinfo
            )
            assert timestamp <= alert.timestamp
            assert (alert.timestamp - timestamp).total_seconds() <= 7 * 86400
