"""Structural contracts shared by orchestration and implementations.

Importing the data contracts here gives pipeline.py one dependency
surface without importing concrete adapters.
"""

from collections.abc import Iterable
from datetime import datetime
from typing import Literal, Protocol

from network_dork.models import (
    Alert,
    AlertContext,
    AuditEvent,
    FailureRecord,
    InvestigationReport,
)

class AlertSource(Protocol):
    def poll(self) -> Iterable[Alert]: ...

class ContextProvider(Protocol):
    def gather(self, alert: Alert) -> AlertContext: ...

class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...

class ReportSink(Protocol):
    def write(self, source: str, report: InvestigationReport) -> None: ...

class AuditLog(Protocol):
    def record(self, event: AuditEvent) -> None: ...

class FailureStore(Protocol):
    def write_failure(self, source: str, failure: FailureRecord) -> None: ...

class OutcomeReader(Protocol):
    # Keyed by (source, alert_id): two sources may reuse a native identifier.
    def get_outcome(
        self, source: str, alert_id: str
    ) -> InvestigationReport | FailureRecord | None: ...

class ProcessedAlertStore(Protocol):
    def claim(
        self,
        source: str,
        alert_id: str,
        owner: str,
        now: datetime,
        lease_seconds: int,
    ) -> bool: ...

    def renew(
        self,
        source: str,
        alert_id: str,
        owner: str,
        now: datetime,
        lease_seconds: int,
    ) -> bool: ...

    def finish(
        self,
        source: str,
        alert_id: str,
        owner: str,
        outcome: Literal["succeeded", "failed"],
        now: datetime,
    ) -> None: ...

class PromptRenderer(Protocol):
    def render(self, context: AlertContext) -> tuple[str, str]: ...
