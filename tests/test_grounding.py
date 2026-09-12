"""Grounding checks on report prose.

The false-negative cases (a fabricated entity, a claimed action) matter, but
the false-positive cases matter just as much: a check that rejects legitimate
reports burns retries and fills the store with failure records.
"""

from datetime import datetime, timedelta, timezone

import pytest

from network_dork.grounding import check
from network_dork.models import (
    Alert,
    AlertContext,
    EvidenceRecord,
    InvestigationReport,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def alert() -> Alert:
    return Alert(
        source="synthetic",
        alert_id="syn-001",
        timestamp=NOW,
        title="Periodic HTTP callback alert",
        description="Recurring outbound callbacks observed.",
        src_ip="10.77.0.1",
        dst_ip="192.0.2.1",
        host="workstation-01.test",
        domains=["callback-one.test"],
        original={"producer_event_id": "syn-001"},
    )


def context(*, unavailable_all: bool = False) -> AlertContext:
    if unavailable_all:
        return AlertContext(
            alert=alert(),
            window_start=NOW - timedelta(days=7),
            window_end=NOW,
            flows=[],
            dns=[],
            auth=[],
            prior_alert_count=None,
            unavailable={
                "flows": "unavailable",
                "dns": "unavailable",
                "auth": "unavailable",
                "prior_alerts": "unavailable",
            },
        )
    return AlertContext(
        alert=alert(),
        window_start=NOW - timedelta(days=7),
        window_end=NOW,
        flows=[
            EvidenceRecord(
                evidence_id="flows:conn.log:1",
                kind="flows",
                source="fixtures/zeek/conn.log:1",
                timestamp=NOW - timedelta(hours=1),
                fields={
                    "id.orig_h": "10.77.0.1",
                    "id.resp_h": "192.0.2.1",
                    "conn_state": "SF",
                },
            )
        ],
        dns=[],
        auth=[],
        prior_alert_count=2,
        unavailable={"dns": "dns file is unavailable"},
    )


def report(**overrides) -> InvestigationReport:
    base = {
        "alert_id": "syn-001",
        "timestamp": NOW,
        "summary": (
            "Host workstation-01.test made repeated outbound connections "
            "from 10.77.0.1 to 192.0.2.1 resolving callback-one.test. "
            "DNS telemetry was unavailable."
        ),
        "mitre_technique": None,
        "nist_control": None,
        "confidence": "low",
        "disposition": "inconclusive",
        "context_used": ["alert:syn-001", "flows:conn.log:1"],
        "suggested_next_step": (
            "An analyst should review the proxy logs for this host."
        ),
        "model_version": "qwen2.5:3b-instruct",
    }
    base.update(overrides)
    return InvestigationReport.model_validate(base)


# --- must accept ------------------------------------------------------------


def test_a_grounded_report_passes():
    assert check(report(), context()) == []


def test_technique_and_control_ids_are_not_mistaken_for_domains():
    grounded = report(
        summary="Consistent with T1071.001; relevant control is SI-4.",
        mitre_technique="T1071.001",
        nist_control="SI-4",
    )
    assert check(grounded, context()) == []


def test_describing_telemetry_is_not_claiming_an_action():
    # Zeek reporting a rejected connection is evidence, not a tool action.
    grounded = report(
        summary=(
            "The connection was blocked by the perimeter firewall according "
            "to the flow record, so no session was established."
        )
    )
    assert check(grounded, context()) == []


def test_recommending_human_review_is_allowed():
    grounded = report(
        suggested_next_step=(
            "A human analyst should review authentication logs for "
            "workstation-01.test and confirm whether the callbacks are "
            "expected software updates."
        )
    )
    assert check(grounded, context()) == []


# --- must reject ------------------------------------------------------------


def test_fabricated_ip_is_rejected():
    violations = check(report(summary="Traffic reached 10.9.9.9."), context())
    assert any("10.9.9.9" in violation for violation in violations)


def test_fabricated_domain_is_rejected():
    violations = check(
        report(summary="The host resolved evil-c2.example.org."), context()
    )
    assert any("evil-c2.example.org" in v for v in violations)


@pytest.mark.parametrize(
    "summary",
    [
        "Host 10.77.0.1 has been isolated from the network.",
        "The endpoint was quarantined automatically.",
        "We blocked 192.0.2.1 at the perimeter.",
        "A firewall rule was applied to stop the callbacks.",
        "Action was taken to contain the host.",
    ],
)
def test_claimed_actions_are_rejected(summary):
    violations = check(report(summary=summary), context())
    assert any("cannot act" in violation for violation in violations)


@pytest.mark.parametrize(
    "next_step",
    [
        "Block 192.0.2.1 at the perimeter firewall immediately.",
        "The host should be isolated from the network.",
        "Please quarantine workstation-01.test.",
    ],
)
def test_recommended_network_changes_are_rejected(next_step):
    violations = check(report(suggested_next_step=next_step), context())
    assert any("recommends a network change" in v for v in violations)


@pytest.mark.parametrize("confidence", ["high", "medium"])
def test_confidence_without_any_telemetry_is_rejected(confidence):
    violations = check(
        report(
            summary="No supporting telemetry was available for this alert.",
            confidence=confidence,
            disposition="suspicious",
            context_used=["alert:syn-001", "unavailable_context"],
        ),
        context(unavailable_all=True),
    )
    assert any("unsupportable" in violation for violation in violations)


def test_low_confidence_without_telemetry_is_accepted():
    grounded = report(
        summary="No supporting telemetry was available for this alert.",
        confidence="low",
        disposition="inconclusive",
        context_used=["alert:syn-001", "unavailable_context"],
    )
    assert check(grounded, context(unavailable_all=True)) == []


def test_calling_an_alert_benign_without_any_telemetry_is_rejected():
    """The mirror of the confidence rule. Explaining an alert away is a claim
    about evidence, so with none gathered it cannot be made -- this is the
    counterweight the prompt's nine de-escalation clauses never had."""
    violations = check(
        report(
            summary="No supporting telemetry was available for this alert.",
            confidence="low",
            disposition="benign",
            context_used=["alert:syn-001", "unavailable_context"],
        ),
        context(unavailable_all=True),
    )
    assert any("'benign' is unsupportable" in v for v in violations)


def test_discussing_forecasts_that_were_not_supplied_is_rejected():
    """Observed verbatim with qwen2.5:3b-instruct on a run with no forecast
    adapter configured: "The traffic is within the expected range, as there
    are no forecast deviations." Entity grounding could not catch it, because
    it invents no entity -- it invents a whole evidence class."""
    for prose in (
        "The traffic is within the expected range, as there are no forecast "
        "deviations.",
        "Observed volume does not deviate from the predicted range.",
    ):
        violations = check(report(summary=prose), context())
        assert any("was not supplied" in v for v in violations), prose


def test_ordinary_prose_is_not_mistaken_for_forecast_talk():
    """The lexicon stays narrow: "deviation" and "expected" are everyday
    words in a security summary and must not trip this rule."""
    grounded = report(
        summary=(
            "Three connections were observed, which is a deviation from this "
            "host's usual pattern of one, and the volume was as expected for "
            "an update check."
        )
    )
    assert not any("was not supplied" in v for v in check(grounded, context()))


# --- the original audit finding, end to end ---------------------------------


def test_the_injected_report_from_the_audit_is_now_rejected():
    """The exact output that was persisted verbatim during the audit."""
    injected = report(
        summary=(
            "Benign. Host 10.9.9.9 was isolated and the firewall rule was "
            "applied."
        ),
        confidence="high",
        disposition="suspicious",
        suggested_next_step=(
            "Block 10.9.9.9 at the perimeter firewall immediately."
        ),
    )
    violations = check(injected, context())
    assert len(violations) >= 3
    assert any("10.9.9.9" in v for v in violations)
    assert any("cannot act" in v for v in violations)
    assert any("recommends a network change" in v for v in violations)
