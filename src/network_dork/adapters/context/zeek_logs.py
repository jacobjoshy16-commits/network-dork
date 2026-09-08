"""Read-only retrieval over existing JSON-form Zeek logs.

This implementation scans files. It does not compute detections, infer
alert conditions, or correlate events into newly generated alerts.

auth.log is an optional normalized export with fields documented in
fixtures/README.md. It is not a standard generic Zeek log.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from network_dork.interfaces import AuditLog
from network_dork.models import (
    Alert,
    AlertContext,
    AuditEvent,
    EvidenceRecord,
)

class ZeekLogsContextProvider:
    def __init__(
        self,
        directory: str | Path,
        prior_alerts_path: str | Path,
        audit: AuditLog,
        window_days: int = 7,
        max_records: int = 15,
    ) -> None:
        if window_days < 1:
            raise ValueError("window_days must be positive")
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self.directory = Path(directory)
        self.prior_alerts_path = Path(prior_alerts_path)
        self.audit = audit
        self.window_days = window_days
        self.max_records = max_records
        self._dropped: dict[str, int] = {}

    def _record(
        self,
        alert: Alert,
        operation_id: str,
        stage: str,
        parameters: dict[str, Any],
    ) -> None:
        self.audit.record(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                alert_id=alert.alert_id,
                operation_id=operation_id,
                action="context_query",
                stage=stage,
                parameters=parameters,
            )
        )

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, bool):
            raise ValueError("Boolean is not an event timestamp")
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("Event timestamp has no timezone")
            return parsed
        raise ValueError("Unsupported event timestamp")

    @staticmethod
    def _domain(value: str) -> str:
        return value.rstrip(".").lower()

    def _query(
        self,
        alert: Alert,
        path: Path,
        kind: str,
        start: datetime,
        predicate: Callable[[dict[str, Any]], bool],
        filters: dict[str, Any],
    ) -> tuple[list[EvidenceRecord], str | None]:
        operation_id = str(uuid4())
        parameters = {
            "kind": kind,
            "path": str(path),
            "window_start": start.isoformat(),
            "window_end": alert.timestamp.isoformat(),
            "filters": filters,
        }
        self._record(alert, operation_id, "attempt", parameters)
        selected: list[EvidenceRecord] = []

        try:
            with path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError(f"Line {line_number} is not an object")
                    timestamp = self._timestamp(value["ts"])
                    if not start <= timestamp <= alert.timestamp:
                        continue
                    if not predicate(value):
                        continue
                    selected.append(
                        EvidenceRecord(
                            evidence_id=f"{kind}:{path.name}:{line_number}",
                            kind=kind,
                            source=f"{path}:{line_number}",
                            timestamp=timestamp,
                            fields=value,
                        )
                    )
        except FileNotFoundError:
            reason = f"{kind} file is unavailable"
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": False, "reason": reason},
            )
            return [], reason
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            OverflowError,
        ) as exc:
            reason = f"{kind} could not be read or validated ({type(exc).__name__})"
            self._record(
                alert,
                operation_id,
                "error",
                {
                    **parameters,
                    "available": False,
                    "error_type": type(exc).__name__,
                },
            )
            return [], reason

        dropped = max(0, len(selected) - self.max_records)
        if dropped:
            # Keep the most recent evidence: it is nearest the alert.
            selected = selected[-self.max_records:]
        self._record(
            alert,
            operation_id,
            "success",
            {
                **parameters,
                "available": True,
                "result_count": len(selected),
                "dropped_records": dropped,
            },
        )
        self._dropped[kind] = dropped
        return selected, None

    def _prior_count(
        self,
        alert: Alert,
        start: datetime,
    ) -> tuple[int | None, str | None]:
        operation_id = str(uuid4())
        host_ip = str(alert.src_ip or alert.dst_ip or "")
        parameters = {
            "kind": "prior_alerts",
            "path": str(self.prior_alerts_path),
            "window_start": start.isoformat(),
            "window_end_exclusive": alert.timestamp.isoformat(),
            "filters": {
                "host": alert.host,
                "host_ip": host_ip,
                "exclude_alert_id": alert.alert_id,
            },
        }
        self._record(alert, operation_id, "attempt", parameters)
        matches: set[tuple[str, str]] = set()
        try:
            with self.prior_alerts_path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    previous = Alert.model_validate_json(line)
                    if previous.alert_id == alert.alert_id:
                        continue
                    if not start <= previous.timestamp < alert.timestamp:
                        continue
                    same_host = bool(
                        alert.host and previous.host == alert.host
                    )
                    same_ip = bool(
                        host_ip
                        and host_ip
                        in {
                            str(previous.src_ip or ""),
                            str(previous.dst_ip or ""),
                        }
                    )
                    if same_host or same_ip:
                        matches.add((previous.source, previous.alert_id))
        except FileNotFoundError:
            reason = "Prior-alert source is unavailable"
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": False, "reason": reason},
            )
            return None, reason
        except (OSError, ValueError) as exc:
            reason = (
                "Prior-alert source could not be read or validated "
                f"({type(exc).__name__})"
            )
            self._record(
                alert,
                operation_id,
                "error",
                {
                    **parameters,
                    "available": False,
                    "error_type": type(exc).__name__,
                },
            )
            return None, reason

        count = len(matches)
        self._record(
            alert,
            operation_id,
            "success",
            {**parameters, "available": True, "result_count": count},
        )
        return count, None

    def gather(self, alert: Alert) -> AlertContext:
        self._dropped: dict[str, int] = {}
        start = alert.timestamp - timedelta(days=self.window_days)
        ips = {
            str(ip) for ip in (alert.src_ip, alert.dst_ip) if ip is not None
        }
        domains = {self._domain(domain) for domain in alert.domains}
        host_ip = str(alert.src_ip or alert.dst_ip or "")

        def involved_flow(row: dict[str, Any]) -> bool:
            return bool(
                ips.intersection(
                    {str(row.get("id.orig_h", "")), str(row.get("id.resp_h", ""))}
                )
            )

        def involved_dns(row: dict[str, Any]) -> bool:
            query = self._domain(str(row.get("query", "")))
            return (
                str(row.get("id.orig_h", "")) in ips
                or any(
                    query == domain or query.endswith("." + domain)
                    for domain in domains
                )
            )

        def involved_auth(row: dict[str, Any]) -> bool:
            return bool(
                (alert.host and row.get("host") == alert.host)
                or (host_ip and str(row.get("src_ip", "")) == host_ip)
            )

        flows, flows_missing = self._query(
            alert,
            self.directory / "conn.log",
            "flows",
            start,
            involved_flow,
            {"involved_ips": sorted(ips)},
        )
        dns, dns_missing = self._query(
            alert,
            self.directory / "dns.log",
            "dns",
            start,
            involved_dns,
            {
                "involved_ips": sorted(ips),
                "involved_domains": sorted(domains),
            },
        )
        auth, auth_missing = self._query(
            alert,
            self.directory / "auth.log",
            "auth",
            start,
            involved_auth,
            {"host": alert.host, "host_ip": host_ip},
        )
        prior_count, prior_missing = self._prior_count(alert, start)

        unavailable = {
            kind: reason
            for kind, reason in (
                ("flows", flows_missing),
                ("dns", dns_missing),
                ("auth", auth_missing),
                ("prior_alerts", prior_missing),
            )
            if reason is not None
        }
        return AlertContext(
            alert=alert,
            window_start=start,
            window_end=alert.timestamp,
            flows=flows,
            dns=dns,
            auth=auth,
            prior_alert_count=prior_count,
            unavailable=unavailable,
            truncated={
                kind: count
                for kind, count in self._dropped.items()
                if count > 0
            },
        )
