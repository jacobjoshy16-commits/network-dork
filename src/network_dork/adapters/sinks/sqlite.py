"""SQLite canonical outcomes with audited, idempotent persistence.

alert_id must be globally unique across configured alert sources.
Normalizers for remote sources must namespace their native event IDs.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sqlite3
from uuid import uuid4

from network_dork.interfaces import AuditLog
from network_dork.models import (
    AuditEvent,
    FailureRecord,
    InvestigationReport,
)

class OutcomeConflictError(RuntimeError):
    pass

class SQLiteReportSink:
    def __init__(self, path: str | Path, audit: AuditLog) -> None:
        self.path = Path(path)
        self.audit = audit
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS outcomes (
                    alert_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('report', 'failure')),
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            connection.execute("""
                CREATE VIEW IF NOT EXISTS reports AS
                SELECT alert_id, timestamp, payload
                FROM outcomes WHERE kind='report'
            """)
            connection.execute("""
                CREATE VIEW IF NOT EXISTS failures AS
                SELECT alert_id, timestamp, payload
                FROM outcomes WHERE kind='failure'
            """)

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def _audit(
        self,
        alert_id: str,
        operation_id: str,
        action: str,
        stage: str,
        parameters: dict,
    ) -> None:
        self.audit.record(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                alert_id=alert_id,
                operation_id=operation_id,
                action=action,
                stage=stage,
                parameters=parameters,
            )
        )

    def _write(
        self,
        value: InvestigationReport | FailureRecord,
        kind: str,
    ) -> None:
        operation_id = str(uuid4())
        payload = value.model_dump_json()
        action = "report_write" if kind == "report" else "failure_write"
        parameters = {
            "sink": "sqlite",
            "path": str(self.path),
            "kind": kind,
            "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
            "document": value.model_dump(mode="json"),
        }
        self._audit(
            value.alert_id, operation_id, action, "attempt", parameters
        )
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                previous = connection.execute(
                    "SELECT kind, payload FROM outcomes WHERE alert_id=?",
                    (value.alert_id,),
                ).fetchone()
                inserted = previous is None
                if previous is None:
                    connection.execute(
                        "INSERT INTO outcomes VALUES (?, ?, ?, ?)",
                        (
                            value.alert_id,
                            kind,
                            value.timestamp.isoformat(),
                            payload,
                        ),
                    )
                elif previous != (kind, payload):
                    raise OutcomeConflictError(
                        "A different canonical outcome already exists "
                        f"for {value.alert_id}"
                    )
        except Exception as exc:
            self._audit(
                value.alert_id,
                operation_id,
                action,
                "error",
                {**parameters, "error_type": type(exc).__name__},
            )
            raise

        self._audit(
            value.alert_id,
            operation_id,
            action,
            "success",
            {**parameters, "inserted": inserted},
        )

    def write(self, report: InvestigationReport) -> None:
        self._write(report, "report")

    def write_failure(self, failure: FailureRecord) -> None:
        self._write(failure, "failure")

    def get_outcome(
        self, alert_id: str
    ) -> InvestigationReport | FailureRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT kind, payload FROM outcomes WHERE alert_id=?",
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        kind, payload = row
        if kind == "report":
            return InvestigationReport.model_validate_json(payload)
        return FailureRecord.model_validate_json(payload)
