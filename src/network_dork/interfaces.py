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
    Forecast,
    InvestigationReport,
    TimeSeries,
)

class AlertSource(Protocol):
    def poll(self) -> Iterable[Alert]: ...

class ContextProvider(Protocol):
    def gather(self, alert: Alert) -> AlertContext: ...

class TimeSeriesProvider(Protocol):
    """Bucket existing telemetry into a regular series for one entity.

    Read-only, like every other telemetry path. Raises InsufficientHistory
    when the entity has too little history to forecast against.
    """

    def series(
        self,
        *,
        metric: str,
        entity: str,
        end: datetime,
        buckets: int,
        bucket_seconds: int,
    ) -> TimeSeries: ...

class Forecaster(Protocol):
    """Predict the continuation of a series with an uncertainty band.

    Implementations are pure predictors. They never decide that a deviation
    is malicious, and they never emit alerts.
    """

    def forecast(self, series: TimeSeries, horizon: int) -> Forecast: ...

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

class GroundingCheck(Protocol):
    """Return violations found in a report's prose; empty means acceptable."""

    def __call__(
        self, report: InvestigationReport, context: AlertContext
    ) -> list[str]: ...
