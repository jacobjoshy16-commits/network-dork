"""Investigation orchestration.

No concrete adapters, database drivers, HTTP clients, or prompt
implementations are imported here.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from network_dork.interfaces import (
    Alert,
    AlertContext,
    AlertSource,
    ContextProvider,
    FailureRecord,
    FailureStore,
    InvestigationReport,
    LLMClient,
    OutcomeReader,
    ProcessedAlertStore,
    PromptRenderer,
    ReportSink,
)

class PipelineLeaseLost(RuntimeError):
    pass

class InvestigationPipeline:
    def __init__(
        self,
        *,
        source: AlertSource,
        context: ContextProvider,
        llm: LLMClient,
        sink: ReportSink,
        failures: FailureStore,
        outcomes: OutcomeReader,
        state: ProcessedAlertStore,
        prompts: PromptRenderer,
        model_version: str,
        max_attempts: int = 3,
        lease_seconds: int = 600,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        self.source = source
        self.context = context
        self.llm = llm
        self.sink = sink
        self.failures = failures
        self.outcomes = outcomes
        self.state = state
        self.prompts = prompts
        self.model_version = model_version
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.owner = str(uuid4())

    def _renew(self, alert: Alert) -> None:
        if not self.state.renew(
            alert.source,
            alert.alert_id,
            self.owner,
            self.clock(),
            self.lease_seconds,
        ):
            raise PipelineLeaseLost(
                f"Lost processing lease for {alert.alert_id}"
            )

    def _finish(self, alert: Alert, status: str) -> None:
        self.state.finish(
            alert.source,
            alert.alert_id,
            self.owner,
            status,
            self.clock(),
        )

    def _failure(
        self,
        alert: Alert,
        attempts: int,
        category: str,
        errors: list[str],
    ) -> FailureRecord:
        identity = f"{alert.source}\0{alert.alert_id}"
        return FailureRecord(
            failure_id=hashlib.sha256(identity.encode()).hexdigest(),
            alert_id=alert.alert_id,
            timestamp=self.clock(),
            model_version=self.model_version,
            attempts=attempts,
            category=category,
            errors=errors,
        )

    @staticmethod
    def _validate_response(
        raw: str,
        alert: Alert,
        context: AlertContext,
        model_version: str,
        user_prompt: str,
    ) -> InvestigationReport:
        report = InvestigationReport.model_validate_json(raw)
        if report.alert_id != alert.alert_id:
            raise ValueError("Model returned the wrong alert_id")
        if report.model_version != model_version:
            raise ValueError("Model returned the wrong model_version")

        request = json.loads(user_prompt)
        expected_timestamp = datetime.fromisoformat(
            request["required_identity"]["timestamp"].replace("Z", "+00:00")
        )
        if report.timestamp != expected_timestamp:
            raise ValueError("Model returned the wrong report timestamp")

        allowed = {f"alert:{alert.alert_id}"}
        for group in (context.flows, context.dns, context.auth):
            allowed.update(record.evidence_id for record in group)
        if context.prior_alert_count is not None:
            allowed.add("prior_alert_count")
        if context.unavailable:
            allowed.add("unavailable_context")
        if not set(report.context_used).issubset(allowed):
            raise ValueError("Model cited an unknown context identifier")
        return report

    def run_once(
        self,
    ) -> list[InvestigationReport | FailureRecord]:
        completed: list[InvestigationReport | FailureRecord] = []

        for alert in self.source.poll():
            claimed = self.state.claim(
                alert.source,
                alert.alert_id,
                self.owner,
                self.clock(),
                self.lease_seconds,
            )
            if not claimed:
                continue

            existing = self.outcomes.get_outcome(alert.alert_id)
            if existing is not None:
                self._renew(alert)
                if isinstance(existing, InvestigationReport):
                    self.sink.write(existing)
                    self._finish(alert, "succeeded")
                else:
                    self.failures.write_failure(existing)
                    self._finish(alert, "failed")
                completed.append(existing)
                continue

            gathered = self.context.gather(alert)
            self._renew(alert)
            system, user = self.prompts.render(gathered)

            errors: list[str] = []
            category = "invalid_model_output"
            report: InvestigationReport | None = None

            for attempt in range(1, self.max_attempts + 1):
                self._renew(alert)
                try:
                    raw = self.llm.complete(system, user)
                except Exception as exc:
                    category = "llm_unavailable"
                    errors.append(
                        f"attempt {attempt}: LLM call failed "
                        f"({type(exc).__name__})"
                    )
                    continue

                try:
                    report = self._validate_response(
                        raw,
                        alert,
                        gathered,
                        self.model_version,
                        user,
                    )
                except (ValueError, TypeError) as exc:
                    category = "invalid_model_output"
                    errors.append(
                        f"attempt {attempt}: invalid model output "
                        f"({type(exc).__name__}): {str(exc)[:2000]}"
                    )
                    report = None
                    continue
                break

            self._renew(alert)
            if report is not None:
                self.sink.write(report)
                self._finish(alert, "succeeded")
                completed.append(report)
            else:
                failure = self._failure(
                    alert,
                    self.max_attempts,
                    category,
                    errors,
                )
                self.failures.write_failure(failure)
                self._finish(alert, "failed")
                completed.append(failure)

        return completed
