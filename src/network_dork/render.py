"""Human-readable rendering of contexts and reports.

The product goal is an analyst reading one screen and forming a judgement
quickly. JSON is the storage format; this is the reading format.

Nothing here interprets or summarizes further. It lays out what the model
already said, what evidence backed it, and what was missing, so a person can
disagree with the report by looking at the same things it looked at.
"""

from __future__ import annotations

import textwrap

from network_dork.models import AlertContext, FailureRecord, InvestigationReport

WIDTH = 76
RULE = "-" * WIDTH


def _wrap(text: str, indent: str = "  ") -> str:
    return textwrap.fill(
        text.strip(),
        width=WIDTH,
        initial_indent=indent,
        subsequent_indent=indent,
    )


def _endpoints(context: AlertContext) -> str:
    alert = context.alert
    parts = []
    if alert.src_ip:
        parts.append(str(alert.src_ip))
    if alert.dst_ip:
        parts.append(str(alert.dst_ip))
    line = " -> ".join(parts) if parts else ""
    if alert.host:
        line = f"{line}   host {alert.host}" if line else f"host {alert.host}"
    if alert.domains:
        line = f"{line}   {', '.join(alert.domains)}" if line else ", ".join(alert.domains)
    return line


def render_evidence(context: AlertContext) -> str:
    """One line per evidence kind: what was found, or why it was not."""
    lines = []
    counts = [
        ("flows", len(context.flows)),
        ("dns", len(context.dns)),
        ("auth", len(context.auth)),
        ("forecast", len(context.forecast)),
    ]
    for kind, count in counts:
        if kind in context.unavailable:
            lines.append(f"  {kind:<10} unavailable - {context.unavailable[kind]}")
        else:
            dropped = context.truncated.get(kind, 0)
            extra = f"  ({dropped} more not shown)" if dropped else ""
            lines.append(f"  {kind:<10} {count} record(s){extra}")

    if "prior_alerts" in context.unavailable:
        lines.append(
            f"  {'prior':<10} unavailable - {context.unavailable['prior_alerts']}"
        )
    else:
        lines.append(f"  {'prior':<10} {context.prior_alert_count} earlier alert(s)")
    return "\n".join(lines)


def render_forecast(context: AlertContext) -> str:
    """Spell out each forecast observation in words, not just numbers."""
    if not context.forecast:
        reason = context.unavailable.get("forecast")
        return f"  none - {reason}" if reason else "  none"

    lines = []
    for record in context.forecast:
        fields = record.fields
        low, high = fields.get("predicted_range", [0, 0])
        # A symmetric band around a small prediction can dip below zero.
        # Counts and byte totals cannot, so show the meaningful part. The
        # scoring band deliberately keeps its full width: narrowing it there
        # was measured to add false positives.
        low = max(0.0, low)
        direction = (
            "above" if fields.get("direction") == "above_forecast" else "below"
        )
        lines.append(
            f"  {record.timestamp:%Y-%m-%d %H:%M}  {fields.get('metric', '?'):<22}"
        )
        lines.append(
            f"      observed {fields.get('observed', 0):.1f}, expected "
            f"{low:.1f} to {high:.1f}  ({direction} the usual range)"
        )
    lines.append("")
    lines.append(
        _wrap(
            "This is a statistical observation about traffic volume or rhythm. "
            "It is not a detection and not proof of anything on its own.",
            indent="  ",
        )
    )
    return "\n".join(lines)


def render_report(
    report: InvestigationReport, context: AlertContext | None = None
) -> str:
    """An analyst brief: the finding, then what it rests on."""
    alert_line = ""
    if context is not None:
        alert_line = (
            f"{context.alert.title}\n"
            f"       {context.alert.timestamp:%Y-%m-%d %H:%M UTC}"
            f"   {_endpoints(context)}"
        )

    labels = []
    if report.mitre_technique:
        labels.append(f"MITRE {report.mitre_technique}")
    if report.nist_control:
        labels.append(f"NIST {report.nist_control}")

    out = [
        RULE,
        f"ALERT  {report.alert_id}",
    ]
    if alert_line:
        out.append(f"       {alert_line}")
    out.append(RULE)
    out.append(
        f"CONFIDENCE  {report.confidence.upper():<8}"
        + ("   " + "   ".join(labels) if labels else "")
    )
    out.append("")
    out.append("SUMMARY")
    out.append(_wrap(report.summary))
    out.append("")
    out.append("SUGGESTED NEXT STEP")
    out.append(_wrap(report.suggested_next_step))
    out.append("")
    out.append("BASED ON")
    if report.context_used:
        for identifier in report.context_used:
            out.append(f"  - {identifier}")
    else:
        out.append("  - (the model cited no specific evidence)")

    if context is not None and context.unavailable:
        out.append("")
        out.append("NOT AVAILABLE")
        for kind, reason in sorted(context.unavailable.items()):
            out.append(f"  - {kind}: {reason}")

    out.append("")
    out.append(f"model: {report.model_version}")
    out.append(RULE)
    return "\n".join(out)


def render_failure(failure: FailureRecord) -> str:
    """Why no report exists, in the same shape as one that does."""
    out = [
        RULE,
        f"ALERT  {failure.alert_id}",
        RULE,
        f"NO REPORT   reason: {failure.category}",
        f"            attempts: {failure.attempts}",
        "",
        "WHAT WENT WRONG",
    ]
    for error in failure.errors:
        out.append(_wrap(error, indent="  - ")[:600])
    out.append("")
    out.append(f"model: {failure.model_version}")
    out.append(RULE)
    return "\n".join(out)
