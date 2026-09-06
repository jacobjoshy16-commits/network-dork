"""Read-only context retrieval from existing OpenSearch telemetry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx

from network_dork.adapters.opensearch_common import OpenSearchJsonClient, OpenSearchRequestError
from network_dork.interfaces import AuditLog
from network_dork.models import Alert, AlertContext, AuditEvent, EvidenceRecord


class OpenSearchContextProvider:
    def __init__(
        self,
        *,
        base_url: str,
        flows_index: str,
        dns_index: str,
        auth_index: str,
        prior_alerts_index: str,
        username: str,
        password: str,
        audit: AuditLog,
        window_days: int = 7,
        timeout_seconds: float = 30.0,
        max_hits: int = 500,
        max_response_bytes: int = 1048576,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if window_days < 1:
            raise ValueError("window_days must be positive")
        if max_hits < 1:
            raise ValueError("max_hits must be positive")
        self.audit = audit
        self.window_days = window_days
        self.max_hits = max_hits
        self.flows_index = flows_index
        self.dns_index = dns_index
        self.auth_index = auth_index
        self.prior_alerts_index = prior_alerts_index
        self.client = OpenSearchJsonClient(
            base_url=base_url,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

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
    def _timestamp(document: dict[str, Any]) -> datetime:
        value = (
            document.get("@timestamp")
            or document.get("timestamp")
            or document.get("ts")
        )
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("OpenSearch event timestamp has no timezone")
            return parsed
        raise ValueError("OpenSearch event has no supported timestamp")

    @staticmethod
    def _get(document: dict[str, Any], dotted: str) -> Any:
        current: Any = document
        for part in dotted.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _search_hits(
        self,
        *,
        alert: Alert,
        kind: str,
        index: str,
        body: dict[str, Any],
    ) -> tuple[list[EvidenceRecord], str | None]:
        operation_id = str(uuid4())
        parameters = {"kind": kind, "index": index, "query": body}
        self._record(alert, operation_id, "attempt", parameters)
        try:
            response = self.client.request_json("POST", f"/{index}/_search", body)
        except OpenSearchRequestError as exc:
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "error_type": type(exc).__name__},
            )
            return [], f"{kind} query failed ({type(exc).__name__})"
        if response.status_code == 404:
            reason = f"{kind} index is unavailable"
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": False, "reason": reason},
            )
            return [], reason
        if response.status_code != 200 or not isinstance(response.data, dict):
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "http_status": response.status_code},
            )
            return [], f"{kind} query returned HTTP {response.status_code}"
        hits = response.data.get("hits", {}).get("hits")
        if not isinstance(hits, list):
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "error_type": "InvalidResponse"},
            )
            return [], f"{kind} query returned an invalid response"
        selected: list[EvidenceRecord] = []
        try:
            for hit in hits:
                if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                    raise ValueError("OpenSearch hit is invalid")
                document = hit["_source"]
                selected.append(
                    EvidenceRecord(
                        evidence_id=f"{kind}:{index}:{hit.get('_id', 'no-id')}",
                        kind=kind,
                        source=f"{index}:{hit.get('_id', 'no-id')}",
                        timestamp=self._timestamp(document),
                        fields=document,
                    )
                )
        except (TypeError, ValueError) as exc:
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "error_type": type(exc).__name__},
            )
            return [], f"{kind} results could not be validated ({type(exc).__name__})"
        self._record(
            alert,
            operation_id,
            "success",
            {**parameters, "available": True, "result_count": len(selected)},
        )
        return selected, None

    def _prior_count(self, *, alert: Alert, body: dict[str, Any]) -> tuple[int | None, str | None]:
        operation_id = str(uuid4())
        parameters = {"kind": "prior_alerts", "index": self.prior_alerts_index, "query": body}
        self._record(alert, operation_id, "attempt", parameters)
        try:
            response = self.client.request_json(
                "POST",
                f"/{self.prior_alerts_index}/_count",
                body,
            )
        except OpenSearchRequestError as exc:
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "error_type": type(exc).__name__},
            )
            return None, f"prior_alerts query failed ({type(exc).__name__})"
        if response.status_code == 404:
            reason = "prior_alerts index is unavailable"
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": False, "reason": reason},
            )
            return None, reason
        if response.status_code != 200 or not isinstance(response.data, dict):
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "http_status": response.status_code},
            )
            return None, f"prior_alerts query returned HTTP {response.status_code}"
        count = response.data.get("count")
        if not isinstance(count, int) or count < 0:
            self._record(
                alert,
                operation_id,
                "error",
                {**parameters, "error_type": "InvalidResponse"},
            )
            return None, "prior_alerts query returned an invalid count"
        self._record(
            alert,
            operation_id,
            "success",
            {**parameters, "available": True, "result_count": count},
        )
        return count, None

    def gather(self, alert: Alert) -> AlertContext:
        start = alert.timestamp - timedelta(days=self.window_days)
        ips = [str(ip) for ip in (alert.src_ip, alert.dst_ip) if ip is not None]
        domains = sorted({domain.rstrip(".").lower() for domain in alert.domains})
        host = alert.host
        flow_body = {
            "size": self.max_hits,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start.isoformat(), "lte": alert.timestamp.isoformat()}}},
                    ],
                    "should": [
                        {"terms": {"source.ip": ips}},
                        {"terms": {"destination.ip": ips}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }
        dns_should: list[dict[str, Any]] = [{"terms": {"source.ip": ips}}] if ips else []
        if domains:
            dns_should.append({"terms": {"dns.question.name": domains}})
            dns_should.append({"terms": {"destination.domain": domains}})
        dns_body = {
            "size": self.max_hits,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start.isoformat(), "lte": alert.timestamp.isoformat()}}},
                    ],
                    "should": dns_should,
                    "minimum_should_match": 1 if dns_should else 0,
                }
            },
        }
        auth_should: list[dict[str, Any]] = []
        if host:
            auth_should.append({"term": {"host.name": host}})
        if ips:
            auth_should.append({"terms": {"source.ip": ips}})
        auth_body = {
            "size": self.max_hits,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start.isoformat(), "lte": alert.timestamp.isoformat()}}},
                    ],
                    "should": auth_should,
                    "minimum_should_match": 1 if auth_should else 0,
                }
            },
        }
        prior_should: list[dict[str, Any]] = []
        if host:
            prior_should.append({"term": {"host.name": host}})
        if ips:
            prior_should.append({"terms": {"source.ip": ips}})
            prior_should.append({"terms": {"destination.ip": ips}})
        prior_body = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start.isoformat(), "lt": alert.timestamp.isoformat()}}},
                        {"bool": {"must_not": [{"term": {"event.id": alert.alert_id}}]}},
                    ],
                    "should": prior_should,
                    "minimum_should_match": 1 if prior_should else 0,
                }
            }
        }

        flows, flows_missing = self._search_hits(alert=alert, kind="flows", index=self.flows_index, body=flow_body)
        dns, dns_missing = self._search_hits(alert=alert, kind="dns", index=self.dns_index, body=dns_body)
        auth, auth_missing = self._search_hits(alert=alert, kind="auth", index=self.auth_index, body=auth_body)
        prior_alert_count, prior_missing = self._prior_count(alert=alert, body=prior_body)
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
            prior_alert_count=prior_alert_count,
            unavailable=unavailable,
        )
