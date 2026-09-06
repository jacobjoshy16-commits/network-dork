"""Validated data exchanged between investigation components.

These models represent existing alerts, retrieved evidence, and model
output. They contain no detection or remediation logic.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    model_validator,
)

NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Technique = Annotated[
    str, StringConstraints(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
]
Control = Annotated[
    str, StringConstraints(pattern=r"^[A-Z]{2}-[0-9]+(?:\([0-9]+\))?$")
]

Confidence = Literal["low", "medium", "high"]
EvidenceKind = Literal["flows", "dns", "auth", "prior_alerts"]

class DataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

class Alert(DataModel):
    source: NonEmpty
    alert_id: NonEmpty
    timestamp: AwareDatetime
    title: NonEmpty
    description: str
    src_ip: IPvAnyAddress | None
    dst_ip: IPvAnyAddress | None
    host: NonEmpty | None
    domains: list[NonEmpty]
    original: dict[str, Any]

    @model_validator(mode="after")
    def has_investigation_subject(self) -> "Alert":
        if not any((self.src_ip, self.dst_ip, self.host, self.domains)):
            raise ValueError("An alert must identify an IP, host, or domain")
        return self

class EvidenceRecord(DataModel):
    evidence_id: NonEmpty
    kind: EvidenceKind
    source: NonEmpty
    timestamp: AwareDatetime
    fields: dict[str, Any]

class AlertContext(DataModel):
    alert: Alert
    window_start: AwareDatetime
    window_end: AwareDatetime
    flows: list[EvidenceRecord]
    dns: list[EvidenceRecord]
    auth: list[EvidenceRecord]
    # None means unavailable; zero means queried and no matches.
    prior_alert_count: int | None = Field(ge=0)
    unavailable: dict[EvidenceKind, NonEmpty]

    @model_validator(mode="after")
    def consistent_window_and_kinds(self) -> "AlertContext":
        if self.window_start > self.window_end:
            raise ValueError("Context window is reversed")
        if self.window_end > self.alert.timestamp:
            raise ValueError("Context must not include post-alert time")
        for kind in ("flows", "dns", "auth"):
            records = getattr(self, kind)
            if kind in self.unavailable and records:
                raise ValueError(f"{kind} cannot be both populated and unavailable")
            for record in records:
                if record.kind != kind:
                    raise ValueError(f"Wrong evidence kind in {kind}")
                if not self.window_start <= record.timestamp <= self.window_end:
                    raise ValueError("Evidence timestamp outside context window")
        missing_count = self.prior_alert_count is None
        if missing_count != ("prior_alerts" in self.unavailable):
            raise ValueError(
                "Unavailable prior-alert counts require an explicit reason"
            )
        return self

class InvestigationReport(DataModel):
    # Deliberately no defaults: missing model fields are errors.
    alert_id: NonEmpty
    timestamp: AwareDatetime
    summary: NonEmpty
    mitre_technique: Technique | None
    nist_control: Control | None
    confidence: Confidence
    context_used: list[NonEmpty]
    suggested_next_step: NonEmpty
    model_version: NonEmpty

class AuditEvent(DataModel):
    timestamp: AwareDatetime
    alert_id: NonEmpty
    operation_id: NonEmpty
    action: Literal["context_query", "report_write", "failure_write"]
    stage: Literal["attempt", "success", "error"]
    parameters: dict[str, Any]

class FailureRecord(DataModel):
    failure_id: NonEmpty
    alert_id: NonEmpty
    timestamp: AwareDatetime
    model_version: NonEmpty
    attempts: int = Field(ge=1)
    category: Literal[
        "invalid_model_output",
        "llm_unavailable",
        "context_error",
    ]
    errors: list[NonEmpty] = Field(min_length=1)
