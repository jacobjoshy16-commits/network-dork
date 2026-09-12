"""Validated data exchanged between investigation components.

These models represent existing alerts, retrieved evidence, and model
output. They contain no detection or remediation logic.
"""

from __future__ import annotations

from datetime import datetime, timedelta
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
# Alert identifiers are interpolated into storage keys and REST paths, so they
# are restricted to characters that cannot alter a URL's structure. Source
# adapters normalize native identifiers into this shape; they never reject an
# alert for carrying an awkward native id.
AlertId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@+-]*$",
    ),
]
SourceName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    ),
]
Technique = Annotated[
    str, StringConstraints(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
]
Control = Annotated[
    str, StringConstraints(pattern=r"^[A-Z]{2}-[0-9]+(?:\([0-9]+\))?$")
]

Confidence = Literal["low", "medium", "high"]
# What the evidence supports about the alert, which is a separate question
# from how sure the model is of that answer. One field cannot carry both: a
# report that means "thin evidence" and one that means "nothing to worry
# about" are opposite findings, and scoring could not tell them apart.
Disposition = Literal["benign", "inconclusive", "suspicious"]
EvidenceKind = Literal["flows", "dns", "auth", "prior_alerts", "forecast"]

class DataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

class Alert(DataModel):
    source: SourceName
    alert_id: AlertId
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

class TimeSeries(DataModel):
    """A regularly bucketed metric for one entity.

    Event logs are irregular; forecasting needs evenly spaced observations,
    so telemetry is bucketed before it reaches a forecaster.
    """

    metric: NonEmpty
    entity: NonEmpty
    bucket_seconds: int = Field(ge=1, le=86400)
    start: AwareDatetime
    values: list[float] = Field(min_length=1)

    def timestamp_at(self, index: int) -> datetime:
        return self.start + timedelta(seconds=self.bucket_seconds * index)

class Forecast(DataModel):
    """A predicted continuation of a series, with an uncertainty band."""

    model: NonEmpty
    model_digest: str | None
    median: list[float] = Field(min_length=1)
    lower: list[float] = Field(min_length=1)
    upper: list[float] = Field(min_length=1)

    @model_validator(mode="after")
    def aligned_bands(self) -> "Forecast":
        if not len(self.median) == len(self.lower) == len(self.upper):
            raise ValueError("Forecast band lengths must match the median")
        for low, high in zip(self.lower, self.upper):
            if low > high:
                raise ValueError("Forecast lower bound exceeds upper bound")
        return self

class AlertContext(DataModel):
    alert: Alert
    window_start: AwareDatetime
    window_end: AwareDatetime
    flows: list[EvidenceRecord]
    dns: list[EvidenceRecord]
    auth: list[EvidenceRecord]
    # Forecast-versus-actual observations for the pre-alert window. These are
    # statistical observations about volume, never detections.
    forecast: list[EvidenceRecord] = Field(default_factory=list)
    # None means unavailable; zero means queried and no matches.
    prior_alert_count: int | None = Field(ge=0)
    unavailable: dict[EvidenceKind, NonEmpty]
    # Records dropped to keep the prompt inside its budget, per kind. The
    # model is told what it is not seeing rather than left to assume it has
    # the whole picture.
    truncated: dict[EvidenceKind, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def consistent_window_and_kinds(self) -> "AlertContext":
        if self.window_start > self.window_end:
            raise ValueError("Context window is reversed")
        if self.window_end > self.alert.timestamp:
            raise ValueError("Context must not include post-alert time")
        for kind in ("flows", "dns", "auth", "forecast"):
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
    alert_id: AlertId
    timestamp: AwareDatetime
    summary: NonEmpty
    disposition: Disposition
    mitre_technique: Technique | None
    nist_control: Control | None
    confidence: Confidence
    context_used: list[NonEmpty]
    suggested_next_step: NonEmpty
    model_version: NonEmpty

class RuntimeIdentity(DataModel):
    """Who and what produced an audit record.

    NIST SP 800-53 AU-3 requires an audit record to identify the subject
    associated with the event. The audit log stamps this onto every event, so
    individual adapters do not have to carry it.
    """

    run_id: NonEmpty
    user: NonEmpty
    host: NonEmpty
    pid: int = Field(ge=0)

class AuditEvent(DataModel):
    timestamp: AwareDatetime
    alert_id: AlertId
    operation_id: NonEmpty
    action: Literal[
        "context_query",
        "report_write",
        "failure_write",
        "llm_request",
        "llm_response",
    ]
    stage: Literal["attempt", "success", "error"]
    parameters: dict[str, Any]
    # Stamped by the audit log when absent, so callers need not supply it.
    identity: RuntimeIdentity | None = None

class FailureRecord(DataModel):
    failure_id: NonEmpty
    alert_id: AlertId
    timestamp: AwareDatetime
    model_version: NonEmpty
    attempts: int = Field(ge=1)
    category: Literal[
        "invalid_model_output",
        "llm_unavailable",
        "context_error",
    ]
    errors: list[NonEmpty] = Field(min_length=1)
