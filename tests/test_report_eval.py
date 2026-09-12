"""Scoring model-written reports against the labelled fixtures.

The point of this module is to make "would a larger model be better" a
measurement. These tests use scripted outcomes rather than a live model, so
the scoring itself is verifiable without Ollama installed.
"""

from datetime import datetime, timezone
import json

import pytest

from network_dork.adapters.sinks.sqlite import SQLiteReportSink
from network_dork.audit import JsonlAuditLog
from network_dork.models import FailureRecord, InvestigationReport
from network_dork.report_eval import (
    Label,
    ReportScore,
    compare,
    load_labels,
    render_score,
    run_label,
    score_outcome,
    score_run,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

LABELS = {
    "syn-001": Label(
        alert_id="syn-001",
        benign=False,
        category="c2_beaconing",
        mitre_technique="T1071.001",
        nist_control="SI-4",
    ),
    "syn-011": Label(
        alert_id="syn-011",
        benign=True,
        category="benign",
        mitre_technique=None,
        nist_control=None,
    ),
}


def report(
    alert_id: str = "syn-001",
    *,
    technique: str | None = "T1071.001",
    control: str | None = "SI-4",
    confidence: str = "medium",
    disposition: str = "suspicious",
    context_used: list[str] | None = None,
) -> InvestigationReport:
    return InvestigationReport(
        alert_id=alert_id,
        timestamp=NOW,
        summary="Repeating outbound connections to a single destination.",
        disposition=disposition,
        mitre_technique=technique,
        nist_control=control,
        confidence=confidence,
        context_used=(
            ["alert:syn-001", "flow:10.77.0.1->203.0.113.5"]
            if context_used is None
            else context_used
        ),
        suggested_next_step="An analyst should review the destination.",
        model_version="test:scripted",
    )


def failure(alert_id: str = "syn-002") -> FailureRecord:
    return FailureRecord(
        failure_id="f-1",
        alert_id=alert_id,
        timestamp=NOW,
        model_version="test:scripted",
        attempts=3,
        category="invalid_model_output",
        errors=["Report cites evidence that was not supplied: flow:invented"],
    )


def test_labels_load_from_the_shipped_fixture():
    labels = load_labels()
    assert labels["syn-001"].category == "c2_beaconing"
    assert labels["syn-001"].benign is False
    assert any(label.benign for label in labels.values())


def test_a_failure_is_counted_as_attempted_but_not_usable():
    score = ReportScore(model="test")
    score_outcome(score, failure(), LABELS.get("syn-002"))

    assert score.attempted == 1
    assert score.usable == 0
    assert score.usable_rate == 0.0
    assert score.failed[0][0] == "syn-002"
    # The reason is kept: a model that keeps inventing evidence and a model
    # that keeps failing the schema need different responses.
    assert "invented" in score.failed[0][1]


def test_correct_attribution_counts_as_matched():
    score = ReportScore(model="test")
    score_outcome(score, report(), LABELS["syn-001"])

    assert score.usable == 1
    assert score.technique_offered == 1
    assert score.technique_matched == 1
    assert score.control_matched == 1
    assert score.technique_precision == 1.0


def test_a_wrong_technique_is_offered_but_not_matched():
    score = ReportScore(model="test")
    score_outcome(score, report(technique="T1041"), LABELS["syn-001"])

    assert score.technique_offered == 1
    assert score.technique_matched == 0
    assert score.technique_precision == 0.0


def test_declining_to_name_a_technique_is_not_a_wrong_answer():
    """The prompt tells the model to emit null rather than guess.

    A model that follows that instruction must not be scored as if it had
    guessed wrong, or the metric would reward guessing.
    """
    score = ReportScore(model="test")
    score_outcome(
        score, report(technique=None, control=None), LABELS["syn-001"]
    )

    assert score.usable == 1
    assert score.technique_offered == 0
    assert score.technique_matched == 0


def test_high_confidence_on_a_benign_alert_is_recorded():
    score = ReportScore(model="test")
    score_outcome(
        score,
        report(alert_id="syn-011", confidence="high", disposition="suspicious"),
        LABELS["syn-011"],
    )

    assert score.benign_seen == 1
    assert score.benign_overconfident == ["syn-011"]
    assert score.benign_overconfidence_rate == 1.0


def test_calling_a_benign_alert_benign_is_the_right_answer():
    score = ReportScore(model="test")
    score_outcome(
        score,
        report(alert_id="syn-011", confidence="high", disposition="benign"),
        LABELS["syn-011"],
    )

    assert score.benign_seen == 1
    assert score.benign_overconfident == []
    assert score.benign_overconfidence_rate == 0.0


def test_calling_a_malicious_alert_benign_is_recorded():
    """Observed with qwen2.5:3b-instruct on the shipped corpus: nine of nine
    malicious alerts written up as "a known benign pattern", while every
    other column scored perfectly."""
    score = ReportScore(model="test")
    score_outcome(
        score,
        report(alert_id="syn-001", disposition="benign"),
        LABELS["syn-001"],
    )

    assert score.malicious_seen == 1
    assert score.malicious_dismissed == ["syn-001"]
    assert score.malicious_dismissal_rate == 1.0
    assert score.malicious_flagged == []


def test_inconclusive_on_a_malicious_alert_is_neither_credited_nor_charged():
    """Admitting the evidence is thin is honest; it is not a finding."""
    score = ReportScore(model="test")
    score_outcome(
        score,
        report(alert_id="syn-001", disposition="inconclusive"),
        LABELS["syn-001"],
    )

    assert score.malicious_dismissed == []
    assert score.malicious_flagged == []


def test_calling_a_malicious_alert_suspicious_is_credited():
    score = ReportScore(model="test")
    score_outcome(
        score,
        report(alert_id="syn-001", disposition="suspicious", confidence="low"),
        LABELS["syn-001"],
    )

    assert score.malicious_flagged == ["syn-001"]
    assert score.malicious_flag_rate == 1.0


def test_dismissing_every_attack_does_not_score_as_well_calibrated():
    """The hole this metric closes: benign_overconfidence alone cannot tell a
    careful model from one that calls everything benign."""
    score = ReportScore(model="test")
    score_outcome(
        score, report(alert_id="syn-001", disposition="benign"), LABELS["syn-001"]
    )
    score_outcome(
        score, report(alert_id="syn-011", disposition="benign"), LABELS["syn-011"]
    )

    assert score.benign_overconfidence_rate == 0.0
    assert score.malicious_dismissal_rate == 1.0
    assert "attacks called benign 1/1" in render_score(score)


def test_citing_only_the_alert_does_not_count_as_using_evidence():
    """Evidence was gathered and paid for; echoing the alert title ignores it."""
    score = ReportScore(model="test")
    score_outcome(
        score, report(context_used=["alert:syn-001"]), LABELS["syn-001"]
    )

    assert score.cited_alert_only == 1
    assert score.cited_evidence == 0
    assert score.evidence_use_rate == 0.0


def test_an_unlabelled_alert_still_counts_toward_usable_output():
    """An operator's own alerts have no labels; the run is still scoreable."""
    score = ReportScore(model="test")
    score_outcome(score, report(alert_id="unlabelled-1"), None)

    assert score.attempted == 1
    assert score.usable == 1
    assert score.technique_offered == 0
    assert score.benign_seen == 0


def write_run(tmp_path, outcomes, model="qwen2.5:3b-instruct"):
    directory = tmp_path / model.replace(":", "-")
    directory.mkdir()
    audit = JsonlAuditLog(directory / "audit.jsonl")
    sink = SQLiteReportSink(directory / "reports.sqlite3", audit)
    for outcome in outcomes:
        if isinstance(outcome, FailureRecord):
            sink.write_failure("synthetic", outcome)
        else:
            sink.write("synthetic", outcome)
    (directory / "manifest.json").write_text(
        json.dumps({"llm": {"model": model}}), encoding="utf-8"
    )
    return directory


def test_scoring_reads_a_run_written_by_the_real_sink(tmp_path):
    """Read through the real schema, not a hand-built table.

    A loader tested against its own fixture proves nothing about whether it
    can read what the pipeline actually wrote.
    """
    directory = write_run(
        tmp_path,
        [
            report(),
            report(alert_id="syn-011", confidence="high"),
            failure(),
        ],
    )

    score = score_run(directory, LABELS)

    assert score.model == "qwen2.5:3b-instruct"
    assert score.attempted == 3
    assert score.usable == 2
    assert score.benign_overconfident == ["syn-011"]


def test_scoring_does_not_write_to_the_run_it_reads(tmp_path):
    """Scoring an archived run must never mutate the evidence."""
    directory = write_run(tmp_path, [report()])
    database = directory / "reports.sqlite3"
    before = database.read_bytes()

    score_run(directory, LABELS)

    assert database.read_bytes() == before


def test_a_missing_database_is_reported_not_scored_as_zero(tmp_path):
    empty = tmp_path / "empty-run"
    empty.mkdir()

    with pytest.raises(FileNotFoundError):
        score_run(empty, LABELS)


def test_a_run_is_named_by_its_model_not_its_directory(tmp_path):
    directory = write_run(tmp_path, [report()], model="qwen2.5:7b-instruct")

    assert run_label(directory) == "qwen2.5:7b-instruct"


def test_a_run_whose_installed_model_differs_is_named_with_both(tmp_path):
    """A manifest asking for 7b on a host serving 3b would invalidate the
    comparison silently; the label carries the discrepancy instead."""
    directory = write_run(tmp_path, [report()], model="qwen2.5:7b-instruct")
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "llm": {"model": "qwen2.5:7b-instruct"},
                "installed_model": "qwen2.5:3b-instruct",
            }
        ),
        encoding="utf-8",
    )

    assert run_label(directory) == (
        "qwen2.5:7b-instruct [qwen2.5:3b-instruct]"
    )


def test_a_run_without_a_manifest_falls_back_to_its_directory(tmp_path):
    directory = write_run(tmp_path, [report()])
    (directory / "manifest.json").unlink()

    assert run_label(directory) == directory.name


def test_rendering_names_the_expensive_mistake(tmp_path):
    score = ReportScore(model="test")
    score_outcome(
        score,
        report(alert_id="syn-011", confidence="high"),
        LABELS["syn-011"],
    )

    rendered = render_score(score)

    assert "benign overconfident" in rendered
    assert "the expensive mistake" in rendered


def test_comparing_two_models_puts_them_on_the_same_rows():
    small = ReportScore(model="qwen2.5:3b-instruct")
    large = ReportScore(model="qwen2.5:7b-instruct")
    score_outcome(small, failure(), None)
    score_outcome(large, report(), LABELS["syn-001"])

    table = compare([small, large])

    assert "qwen2.5:3b-instruct" in table
    assert "qwen2.5:7b-instruct" in table
    assert "benign hi" in table


def test_comparing_nothing_says_so():
    assert compare([]) == "no models scored"
