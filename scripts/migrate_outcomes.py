#!/usr/bin/env python3
"""Migrate a pre-source outcomes database to source-scoped keys.

The original schema keyed outcomes on alert_id alone, which let two alert
sources that reuse a native identifier be handed one another's investigation.
The current schema keys on (source, alert_id).

Old rows carry no source, so one must be supplied. Use the source value the
alerts were originally polled under; it is the "source" field of the alerts in
that deployment's alert file or index.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sqlite3
import sys


def columns(connection: sqlite3.Connection) -> set[str]:
    return {row[1] for row in connection.execute("PRAGMA table_info(outcomes)")}


def migrate(path: Path, source: str, *, backup: bool) -> int:
    if not path.exists():
        raise SystemExit(f"No such database: {path}")

    if backup:
        destination = path.with_suffix(path.suffix + ".pre-source-key.bak")
        if destination.exists():
            raise SystemExit(f"Backup already exists: {destination}")
        shutil.copy2(path, destination)
        print(f"Backed up to {destination}")

    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA busy_timeout=30000")
        with connection:
            present = columns(connection)
            if not present:
                raise SystemExit("No outcomes table found; nothing to migrate")
            if "source" in present:
                print("Already migrated; no changes made.")
                return 0

            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP VIEW IF EXISTS reports")
            connection.execute("DROP VIEW IF EXISTS failures")
            connection.execute("""
                CREATE TABLE outcomes_migrated (
                    source TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('report', 'failure')),
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (source, alert_id)
                )
            """)
            moved = connection.execute(
                """INSERT INTO outcomes_migrated
                   SELECT ?, alert_id, kind, timestamp, payload FROM outcomes""",
                (source,),
            ).rowcount
            connection.execute("DROP TABLE outcomes")
            connection.execute(
                "ALTER TABLE outcomes_migrated RENAME TO outcomes"
            )
            connection.execute("""
                CREATE VIEW reports AS
                SELECT source, alert_id, timestamp, payload
                FROM outcomes WHERE kind='report'
            """)
            connection.execute("""
                CREATE VIEW failures AS
                SELECT source, alert_id, timestamp, payload
                FROM outcomes WHERE kind='failure'
            """)
    finally:
        connection.close()

    print(f"Migrated {moved} outcome(s) under source {source!r}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument(
        "--source",
        required=True,
        help="Source name to attribute existing rows to.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip the .bak copy taken before rewriting the table.",
    )
    args = parser.parse_args()
    return migrate(args.path, args.source, backup=not args.no_backup)


if __name__ == "__main__":
    sys.exit(main())
