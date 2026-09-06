"""JSON Lines outcome sink for simple local artifacts."""

from __future__ import annotations

from pathlib import Path
import threading

from network_dork.interfaces import AuditLog
from network_dork.models import AuditEvent, FailureRecord, InvestigationReport
from datetime import datetime, timezone
from uuid import uuid4


class JsonlOutcomeConflictError(RuntimeError):
    pass


class JsonlReportSink:
    def __init__(self, path: str | Path, audit: AuditLog) -> None:
        self.path = Path(path)
        self.audit = audit
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _audit(self, alert_id: str, action: str, stage: str, parameters: dict) -> None:
        self.audit.record(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                alert_id=alert_id,
                operation_id=str(uuid4()),
                action=action,
                stage=stage,
                parameters=parameters,
            )
        )

    def _read_all(self) -> dict[str, tuple[str, str]]:
        outcomes: dict[str, tuple[str, str]] = {}
        if not self.path.exists():
            return outcomes
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            kind, payload = line.split("\t", 1)
            alert_id = InvestigationReport.model_validate_json(payload).alert_id if kind == "report" else FailureRecord.model_validate_json(payload).alert_id
            outcomes[alert_id] = (kind, payload)
        return outcomes

    def _write(self, value: InvestigationReport | FailureRecord, kind: str) -> None:
        payload = value.model_dump_json()
        action = "report_write" if kind == "report" else "failure_write"
        parameters = {"sink": "jsonl", "path": str(self.path), "kind": kind}
        self._audit(value.alert_id, action, "attempt", parameters)
        with self._lock:
            outcomes = self._read_all()
            previous = outcomes.get(value.alert_id)
            if previous is not None and previous != (kind, payload):
                self._audit(value.alert_id, action, "error", {**parameters, "error_type": "JsonlOutcomeConflictError"})
                raise JsonlOutcomeConflictError(
                    f"A different canonical outcome already exists for {value.alert_id}"
                )
            if previous is None:
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(f"{kind}\t{payload}\n")
        self._audit(value.alert_id, action, "success", {**parameters, "inserted": previous is None})

    def write(self, report: InvestigationReport) -> None:
        self._write(report, "report")

    def write_failure(self, failure: FailureRecord) -> None:
        self._write(failure, "failure")

    def get_outcome(self, alert_id: str) -> InvestigationReport | FailureRecord | None:
        previous = self._read_all().get(alert_id)
        if previous is None:
            return None
        kind, payload = previous
        if kind == "report":
            return InvestigationReport.model_validate_json(payload)
        return FailureRecord.model_validate_json(payload)
