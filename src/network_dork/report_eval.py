"""Score model-written reports against labelled fixtures.

The forecast evaluation answers whether the *forecaster* works. This answers
whether the *language model* does, which is the question behind "would a
larger model be better" -- a question worth a number rather than an opinion.

Four things are measured, in descending order of how much they matter:

**Usable output.** Did the model produce a report at all, or did it fail the
schema and grounding checks until its attempts ran out? A model that writes
beautiful prose one time in three is not usable, however good that one is.

**Disposition, in both directions.** Calling benign traffic suspicious with
high confidence costs an analyst's trust. Calling a real attack benign costs
an incident: an analyst who reads "this is a known benign pattern" on live
C2 closes the ticket. A scorecard that counts only the first direction
reports a model that dismisses everything as perfectly calibrated, so both
are counted -- and both are read from `disposition`, which says what the
model concluded, rather than inferred from `confidence`, which says only how
sure it was.

**Attribution.** Did the MITRE technique and NIST control match the label?
Scored, but weighted lightly: a report can be genuinely useful while
declining to guess a technique, and the prompt explicitly tells it to emit
null rather than guess.

**Evidence use.** Did it cite the evidence it was given, or write from the
alert title alone?

The labels live in fixtures/ground_truth.yaml and never enter a prompt --
tests/test_fixtures.py asserts that separation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import sqlite3
from typing import Any

import yaml

from network_dork.models import FailureRecord, InvestigationReport

DEFAULT_LABELS = Path("fixtures/ground_truth.yaml")


@dataclass(frozen=True)
class Label:
    alert_id: str
    benign: bool
    category: str
    mitre_technique: str | None
    nist_control: str | None


def load_labels(path: Path = DEFAULT_LABELS) -> dict[str, Label]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {
        alert_id: Label(
            alert_id=alert_id,
            benign=bool(entry["benign"]),
            category=str(entry["category"]),
            mitre_technique=entry.get("mitre_technique"),
            nist_control=entry.get("nist_control"),
        )
        for alert_id, entry in raw["alerts"].items()
    }


@dataclass
class ReportScore:
    """What one model achieved across the labelled corpus."""

    model: str
    attempted: int = 0
    usable: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)

    technique_matched: int = 0
    technique_offered: int = 0
    control_matched: int = 0
    control_offered: int = 0

    # Confidence on alerts the labels call benign. High confidence here is
    # the expensive mistake.
    benign_overconfident: list[str] = field(default_factory=list)
    benign_seen: int = 0

    # The mirror image: alerts the labels call malicious and the report
    # calls benign. This is the direction that loses an incident rather than
    # an analyst's patience, and it is the one a small model fails silently.
    malicious_dismissed: list[str] = field(default_factory=list)
    # Correctly called suspicious. The positive counterpart, so a change can
    # be shown to help rather than only to stop hurting.
    malicious_flagged: list[str] = field(default_factory=list)
    malicious_seen: int = 0

    cited_evidence: int = 0
    cited_alert_only: int = 0

    @property
    def usable_rate(self) -> float:
        return self.usable / self.attempted if self.attempted else 0.0

    @property
    def technique_precision(self) -> float:
        """Of the techniques it was willing to name, how many were right."""
        if not self.technique_offered:
            return 0.0
        return self.technique_matched / self.technique_offered

    @property
    def control_precision(self) -> float:
        if not self.control_offered:
            return 0.0
        return self.control_matched / self.control_offered

    @property
    def benign_overconfidence_rate(self) -> float:
        if not self.benign_seen:
            return 0.0
        return len(self.benign_overconfident) / self.benign_seen

    @property
    def malicious_dismissal_rate(self) -> float:
        if not self.malicious_seen:
            return 0.0
        return len(self.malicious_dismissed) / self.malicious_seen

    @property
    def malicious_flag_rate(self) -> float:
        if not self.malicious_seen:
            return 0.0
        return len(self.malicious_flagged) / self.malicious_seen

    @property
    def evidence_use_rate(self) -> float:
        if not self.usable:
            return 0.0
        return self.cited_evidence / self.usable


def score_outcome(
    score: ReportScore,
    outcome: InvestigationReport | FailureRecord,
    label: Label | None,
) -> None:
    """Fold one alert's outcome into a running score."""
    score.attempted += 1

    if isinstance(outcome, FailureRecord):
        reason = outcome.errors[-1] if outcome.errors else outcome.category
        score.failed.append((outcome.alert_id, reason[:160]))
        return

    score.usable += 1

    # Citing only the alert means the evidence was gathered and ignored.
    beyond_alert = [
        item
        for item in outcome.context_used
        if not item.startswith("alert:")
    ]
    if beyond_alert:
        score.cited_evidence += 1
    else:
        score.cited_alert_only += 1

    if label is None:
        return

    if outcome.mitre_technique is not None:
        score.technique_offered += 1
        if outcome.mitre_technique == label.mitre_technique:
            score.technique_matched += 1
    if outcome.nist_control is not None:
        score.control_offered += 1
        if outcome.nist_control == label.nist_control:
            score.control_matched += 1

    if label.benign:
        score.benign_seen += 1
        # Calling ordinary traffic suspicious, and being sure about it.
        if outcome.disposition == "suspicious" and outcome.confidence == "high":
            score.benign_overconfident.append(outcome.alert_id)
    else:
        score.malicious_seen += 1
        if outcome.disposition == "benign":
            score.malicious_dismissed.append(outcome.alert_id)
        elif outcome.disposition == "suspicious":
            score.malicious_flagged.append(outcome.alert_id)


def render_score(score: ReportScore) -> str:
    """A table an operator can compare across models."""
    lines = [
        f"=== {score.model} ===",
        f"  usable reports        {score.usable}/{score.attempted}"
        f"  ({score.usable_rate:.0%})",
    ]
    if score.usable:
        lines.append(
            f"  cited real evidence   {score.cited_evidence}/{score.usable}"
            f"  ({score.evidence_use_rate:.0%})"
        )
        lines.append(
            f"  MITRE offered/right   {score.technique_offered}/"
            f"{score.technique_matched} correct"
            + (
                f"  ({score.technique_precision:.0%} of those named)"
                if score.technique_offered
                else "  (named none, which the prompt permits)"
            )
        )
        lines.append(
            f"  NIST offered/right    {score.control_offered}/"
            f"{score.control_matched} correct"
            + (
                f"  ({score.control_precision:.0%} of those named)"
                if score.control_offered
                else "  (named none, which the prompt permits)"
            )
        )
    if score.malicious_seen:
        lines.append(
            f"  attacks flagged       "
            f"{len(score.malicious_flagged)}/{score.malicious_seen}"
            f"  ({score.malicious_flag_rate:.0%})"
        )
        lines.append(
            f"  attacks called benign "
            f"{len(score.malicious_dismissed)}/{score.malicious_seen}"
            f"  ({score.malicious_dismissal_rate:.0%})"
            + (
                "   <-- the mistake that loses an incident"
                if score.malicious_dismissed
                else ""
            )
        )
    if score.benign_seen:
        lines.append(
            f"  benign overconfident  "
            f"{len(score.benign_overconfident)}/{score.benign_seen}"
            f"  ({score.benign_overconfidence_rate:.0%})"
            + (
                "   <-- the expensive mistake"
                if score.benign_overconfident
                else ""
            )
        )
    if score.failed:
        lines.append(f"  failures ({len(score.failed)}):")
        for alert_id, reason in score.failed[:5]:
            lines.append(f"    {alert_id}: {reason[:100]}")
    return "\n".join(lines)


def compare(scores: list[ReportScore]) -> str:
    """Side by side, so a model choice is a decision rather than a hunch."""
    if not scores:
        return "no models scored"
    header = (
        f"{'model':<28} {'usable':>8} {'evidence':>9} "
        f"{'MITRE ok':>9} {'flagged':>9} {'missed':>9} {'benign hi':>10}"
    )
    rows = [header, "-" * len(header)]
    for score in scores:
        rows.append(
            f"{score.model:<28} {score.usable_rate:>7.0%} "
            f"{score.evidence_use_rate:>8.0%} "
            f"{score.technique_matched:>4}/{score.technique_offered:<4} "
            f"{len(score.malicious_flagged):>4}/{score.malicious_seen:<4} "
            f"{len(score.malicious_dismissed):>4}/{score.malicious_seen:<4} "
            f"{len(score.benign_overconfident):>4}/{score.benign_seen:<5}"
        )
    rows.append("")
    rows.append(
        "A change earns its cost by raising 'flagged' and lowering 'missed' "
        "without raising 'benign hi'."
    )
    return "\n".join(rows)


def load_outcomes(
    database: Path,
) -> list[InvestigationReport | FailureRecord]:
    """Read a run's canonical outcomes without touching its schema.

    Deliberately not the sink: opening this read-only means scoring an old
    run can never migrate, lock, or rewrite it.
    """
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT kind, payload FROM outcomes ORDER BY source, alert_id"
        ).fetchall()
    finally:
        connection.close()
    return [
        InvestigationReport.model_validate_json(payload)
        if kind == "report"
        else FailureRecord.model_validate_json(payload)
        for kind, payload in rows
    ]


def run_label(path: Path) -> str:
    """Name a run by the model that produced it, not by its directory.

    Comparing two runs is only meaningful if each one says which model it
    used, and the manifest is the only place that is recorded.
    """
    manifest = path / "manifest.json"
    if manifest.is_file():
        try:
            data: dict[str, Any] = json.loads(
                manifest.read_text(encoding="utf-8")
            )
        except ValueError:
            return path.name
        model = (data.get("llm") or {}).get("model")
        if model:
            installed = data.get("installed_model")
            # An installed digest that disagrees with the requested tag means
            # the run did not use what the manifest asked for.
            suffix = "" if installed in (None, model) else f" [{installed}]"
            return f"{model}{suffix}"
    return path.name


def score_run(
    path: Path, labels: dict[str, Label], model: str | None = None
) -> ReportScore:
    """Score one run directory or one reports database."""
    if path.is_dir():
        database = path / "reports.sqlite3"
        name = model or run_label(path)
    else:
        database = path
        name = model or path.parent.name
    if not database.is_file():
        raise FileNotFoundError(f"No outcomes database at {database}")

    score = ReportScore(model=name)
    for outcome in load_outcomes(database):
        score_outcome(score, outcome, labels.get(outcome.alert_id))
    return score
