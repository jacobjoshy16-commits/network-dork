import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from network_dork.models import Alert, InvestigationReport

@pytest.fixture
def alert_data():
    line = Path("fixtures/alerts/alerts.jsonl").read_text().splitlines()[0]
    return json.loads(line)

@pytest.fixture
def report_data():
    return {
        "alert_id": "syn-001",
        "timestamp": "2025-01-15T12:01:00Z",
        "summary": "The supplied alert warrants review; intent is uncertain.",
        "mitre_technique": None,
        "nist_control": None,
        "confidence": "low",
        "context_used": ["alert:syn-001"],
        "suggested_next_step": "An analyst should review the available evidence.",
        "model_version": "test-model",
    }

def test_alert_round_trip(alert_data):
    alert = Alert.model_validate(alert_data)
    assert alert.alert_id == "syn-001"
    assert str(alert.src_ip) == "10.77.0.1"
    assert Alert.model_validate_json(alert.model_dump_json()) == alert

@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("src_ip", "999.1.1.1"),
        ("timestamp", "not-a-date"),
        ("timestamp", "2025-01-15T12:00:00"),
        ("alert_id", ""),
        ("title", "   "),
    ],
)
def test_alert_rejects_invalid_fields(alert_data, field, value):
    alert_data[field] = value
    with pytest.raises(ValidationError):
        Alert.model_validate(alert_data)

def test_alert_requires_subject(alert_data):
    alert_data.update(src_ip=None, dst_ip=None, host=None, domains=[])
    with pytest.raises(ValidationError):
        Alert.model_validate(alert_data)

def test_report_round_trip(report_data):
    report = InvestigationReport.model_validate(report_data)
    assert report.mitre_technique is None
    assert report.nist_control is None
    assert InvestigationReport.model_validate_json(report.model_dump_json()) == report

@pytest.mark.parametrize(
    "field",
    [
        "alert_id",
        "timestamp",
        "summary",
        "mitre_technique",
        "nist_control",
        "confidence",
        "context_used",
        "suggested_next_step",
        "model_version",
    ],
)
def test_every_report_field_is_required(report_data, field):
    del report_data[field]
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate(report_data)

@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("confidence", "certain"),
        ("summary", ""),
        ("timestamp", "2025-01-15T12:01:00"),
        ("mitre_technique", "C2"),
        ("nist_control", "NIST"),
        ("context_used", "alert:syn-001"),
    ],
)
def test_report_rejects_invalid_fields(report_data, field, value):
    report_data[field] = value
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate(report_data)

def test_report_rejects_unexpected_fields(report_data):
    report_data["invented_extra"] = True
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate(report_data)

def test_valid_mapping_ids(report_data):
    report_data.update(mitre_technique="T1071.001", nist_control="SI-4")
    report = InvestigationReport.model_validate(report_data)
    assert report.mitre_technique == "T1071.001"
