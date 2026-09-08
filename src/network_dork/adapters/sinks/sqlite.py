"""SQLite canonical outcomes with audited, idempotent persistence.

Outcomes are keyed by ``(source, alert_id)``. The processed-alert store uses
the same key, so two sources that reuse a native identifier cannot be given
one another's investigation.
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

class OutcomeSchemaError(RuntimeError):
    pass

class SQLiteReportSink:
    def __init__(self, path: str | Path, audit: AuditLog) -> None:
        self.path = Path(path)
        self.audit = audit
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            self._guard_legacy_schema(connection)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS outcomes (
                    source TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('report', 'failure')),
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (source, alert_id)
                )
            """)
            connection.execute("""
                CREATE VIEW IF NOT EXISTS reports AS
                SELECT source, alert_id, timestamp, payload
                FROM outcomes WHERE kind='report'
            """)
            connection.execute("""
                CREATE VIEW IF NOT EXISTS failures AS
                SELECT source, alert_id, timestamp, payload
                FROM outcomes WHERE kind='failure'
            """)

    @staticmethod
    def _guard_legacy_schema(connection) -> None:
        """Refuse to run against a pre-source outcomes table.

        The old table keyed outcomes on alert_id alone. Silently adopting it
        would keep the collision it allows, so operators migrate explicitly
        with scripts/migrate_outcomes.py.
        """
        exists = connection.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type='table' AND name='outcomes'"""
        ).fetchone()
        if exists is None:
            return
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(outcomes)")
        }
        if "source" not in columns:
            raise OutcomeSchemaError(
                "This outcomes database predates source-scoped keys. "
                "Migrate it with scripts/migrate_outcomes.py before running."
            )

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
        source: str,
        value: InvestigationReport | FailureRecord,
        kind: str,
    ) -> None:
        operation_id = str(uuid4())
        payload = value.model_dump_json()
        action = "report_write" if kind == "report" else "failure_write"
        parameters = {
            "sink": "sqlite",
            "path": str(self.path),
            "source": source,
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
                    """SELECT kind, payload FROM outcomes
                       WHERE source=? AND alert_id=?""",
                    (source, value.alert_id),
                ).fetchone()
                inserted = previous is None
                if previous is None:
                    connection.execute(
                        "INSERT INTO outcomes VALUES (?, ?, ?, ?, ?)",
                        (
                            source,
                            value.alert_id,
                            kind,
                            value.timestamp.isoformat(),
                            payload,
                        ),
                    )
                elif previous != (kind, payload):
                    raise OutcomeConflictError(
                        "A different canonical outcome already exists "
                        f"for {source}/{value.alert_id}"
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

    def write(self, source: str, report: InvestigationReport) -> None:
        self._write(source, report, "report")

    def write_failure(self, source: str, failure: FailureRecord) -> None:
        self._write(source, failure, "failure")

    def get_outcome(
        self, source: str, alert_id: str
    ) -> InvestigationReport | FailureRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                """SELECT kind, payload FROM outcomes
                   WHERE source=? AND alert_id=?""",
                (source, alert_id),
            ).fetchone()
        if row is None:
            return None
        kind, payload = row
        if kind == "report":
            return InvestigationReport.model_validate_json(payload)
        return FailureRecord.model_validate_json(payload)
