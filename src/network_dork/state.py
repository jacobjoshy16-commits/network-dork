"""Transactional processed-alert claims with recoverable leases."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Literal

class LeaseLostError(RuntimeError):
    pass

class SQLiteState:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS processed_alerts (
                    source TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('in_progress', 'succeeded', 'failed')),
                    owner TEXT NOT NULL,
                    lease_until REAL NOT NULL,
                    attempts INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (source, alert_id)
                )
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

    @staticmethod
    def _epoch(now: datetime) -> float:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("State timestamps must be timezone-aware")
        return now.timestamp()

    def claim(
        self,
        source: str,
        alert_id: str,
        owner: str,
        now: datetime,
        lease_seconds: int,
    ) -> bool:
        epoch = self._epoch(now)
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT status, lease_until FROM processed_alerts
                   WHERE source=? AND alert_id=?""",
                (source, alert_id),
            ).fetchone()
            if row is not None:
                status, lease_until = row
                if status != "in_progress" or lease_until > epoch:
                    return False
                connection.execute(
                    """UPDATE processed_alerts
                       SET owner=?, lease_until=?, attempts=attempts+1,
                           updated_at=?
                       WHERE source=? AND alert_id=?""",
                    (
                        owner,
                        epoch + lease_seconds,
                        epoch,
                        source,
                        alert_id,
                    ),
                )
            else:
                connection.execute(
                    """INSERT INTO processed_alerts
                       VALUES (?, ?, 'in_progress', ?, ?, 1, ?)""",
                    (source, alert_id, owner, epoch + lease_seconds, epoch),
                )
        return True

    def renew(
        self,
        source: str,
        alert_id: str,
        owner: str,
        now: datetime,
        lease_seconds: int,
    ) -> bool:
        epoch = self._epoch(now)
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        with self._connection() as connection:
            result = connection.execute(
                """UPDATE processed_alerts
                   SET lease_until=?, updated_at=?
                   WHERE source=? AND alert_id=? AND owner=?
                     AND status='in_progress' AND lease_until>?""",
                (
                    epoch + lease_seconds,
                    epoch,
                    source,
                    alert_id,
                    owner,
                    epoch,
                ),
            )
            return result.rowcount == 1

    def finish(
        self,
        source: str,
        alert_id: str,
        owner: str,
        outcome: Literal["succeeded", "failed"],
        now: datetime,
    ) -> None:
        if outcome not in {"succeeded", "failed"}:
            raise ValueError("Invalid terminal state")
        epoch = self._epoch(now)
        with self._connection() as connection:
            result = connection.execute(
                """UPDATE processed_alerts
                   SET status=?, updated_at=?, lease_until=0
                   WHERE source=? AND alert_id=? AND owner=?
                     AND status='in_progress' AND lease_until>?""",
                (outcome, epoch, source, alert_id, owner, epoch),
            )
            if result.rowcount != 1:
                raise LeaseLostError("Cannot finish an expired or foreign claim")

    def inspect(self, source: str, alert_id: str) -> dict | None:
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """SELECT * FROM processed_alerts
                   WHERE source=? AND alert_id=?""",
                (source, alert_id),
            ).fetchone()
            return None if row is None else dict(row)
