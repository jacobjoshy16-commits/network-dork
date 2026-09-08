"""Output-side checks on model-authored report prose.

Schema validation proves a report is well formed and cites known evidence
identifiers. It says nothing about the prose, which is what an analyst
actually reads. These checks cover the three ways a report can be well formed
and still wrong:

* it names an entity that appears nowhere in the supplied evidence,
* it claims an action was taken, or recommends one, when this system cannot
  act and is instructed not to recommend acting,
* it expresses confidence that the available context cannot support.

The action lexicons below are deliberately narrow. A broad keyword list
rejects legitimate reports -- "the connection was blocked by the firewall"
describes telemetry rather than claiming the tool acted -- so these patterns
require the report itself to be the actor. Tune them against the evaluation
corpus rather than by adding words speculatively.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from network_dork.models import AlertContext, InvestigationReport

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
# A domain needs an alphabetic final label, which keeps MITRE technique ids
# (T1071.001), NIST controls (SI-4), decimals, and version strings out.
_DOMAIN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)

# The report claiming this system performed or completed an action.
_ACTION_TAKEN = re.compile(
    r"\b("
    r"(?:has|have|had|was|were|been)\s+(?:been\s+)?"
    r"(?:isolated|quarantined|blackholed|remediated|contained|"
    r"disabled|deactivated|reimaged|suspended)"
    r"|(?:i|we|the\s+system|this\s+tool|network-dork)\s+"
    r"(?:have\s+|has\s+)?(?:blocked|isolated|quarantined|disabled|"
    r"terminated|remediated|removed|applied)"
    r"|(?:firewall\s+rule|block\s+rule|acl|policy)\s+"
    r"(?:was|has\s+been|were)\s+(?:applied|added|pushed|deployed|created)"
    r"|action\s+(?:was|has\s+been)\s+taken"
    r"|automatically\s+(?:blocked|isolated|quarantined|disabled)"
    r")\b",
    re.IGNORECASE,
)

# Recommending a change to the network, which the system prompt forbids.
_ACTION_RECOMMENDED = re.compile(
    r"\b("
    r"(?:should|must|please|recommend(?:ed|s)?\s+(?:to\s+)?|immediately)\s+"
    r"(?:be\s+)?(?:block|isolate|quarantine|disable|shut\s+down|"
    r"blackhole|reimage|deactivate|terminate)"
    r"|^\s*(?:block|isolate|quarantine|disable|blackhole|reimage)\b"
    r")",
    re.IGNORECASE | re.MULTILINE,
)


def _strings(value: Any) -> Iterable[str]:
    """Yield every string reachable in a nested evidence structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield str(value)


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _known_entities(context: AlertContext) -> tuple[set[str], set[str]]:
    """Return (ip addresses, domain-ish names) present in supplied context.

    Everything the model was shown counts as grounded, not only what the
    report chose to cite: a report may legitimately mention evidence it did
    not list in context_used.
    """
    blobs: list[str] = []
    alert = context.alert
    for value in (alert.src_ip, alert.dst_ip, alert.host):
        if value is not None:
            blobs.append(str(value))
    blobs.extend(alert.domains)
    blobs.append(alert.title)
    blobs.append(alert.description)
    blobs.extend(_strings(alert.original))
    for group in (
        context.flows,
        context.dns,
        context.auth,
        context.forecast,
    ):
        for record in group:
            blobs.extend(_strings(record.fields))
            blobs.append(record.source)

    ips: set[str] = set()
    names: set[str] = set()
    for blob in blobs:
        for match in _IPV4.findall(blob) + _IPV6.findall(blob):
            normalized = _normalize_ip(match)
            if normalized:
                ips.add(normalized)
        normalized_blob = blob.strip().rstrip(".").lower()
        if normalized_blob:
            names.add(normalized_blob)
        for match in _DOMAIN.findall(blob):
            names.add(match.rstrip(".").lower())
    return ips, names


def check(report: InvestigationReport, context: AlertContext) -> list[str]:
    """Return human-readable grounding violations; empty means acceptable."""
    violations: list[str] = []
    prose = f"{report.summary}\n{report.suggested_next_step}"
    known_ips, known_names = _known_entities(context)

    for match in set(_IPV4.findall(prose) + _IPV6.findall(prose)):
        normalized = _normalize_ip(match)
        if normalized is None:
            continue
        if normalized not in known_ips:
            violations.append(
                f"report names IP {normalized}, which is absent from the "
                "supplied evidence"
            )

    for match in set(_DOMAIN.findall(prose)):
        candidate = match.rstrip(".").lower()
        if _normalize_ip(candidate) is not None:
            continue
        if candidate in known_names:
            continue
        # A parent of a supplied name is a fair generalization; an unrelated
        # name is not.
        if any(
            known == candidate or known.endswith("." + candidate)
            for known in known_names
        ):
            continue
        violations.append(
            f"report names host or domain {candidate!r}, which is absent "
            "from the supplied evidence"
        )

    claimed = _ACTION_TAKEN.search(prose)
    if claimed:
        violations.append(
            "report claims an action was performed "
            f"({claimed.group(0)!r}); this system cannot act"
        )

    recommended = _ACTION_RECOMMENDED.search(report.suggested_next_step)
    if recommended:
        violations.append(
            "suggested_next_step recommends a network change "
            f"({recommended.group(0).strip()!r}); it must recommend review "
            "by a human analyst"
        )

    kinds = {"flows", "dns", "auth", "prior_alerts"}
    if kinds.issubset(context.unavailable) and report.confidence != "low":
        violations.append(
            f"confidence {report.confidence!r} is unsupportable: no "
            "supporting telemetry was available"
        )

    return violations
