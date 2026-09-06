"""OpenSearch report sink with explicit failure records and idempotency."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

import httpx

from network_dork.adapters.opensearch_common import OpenSearchJsonClient, OpenSearchRequestError
from network_dork.interfaces import AuditLog
from network_dork.models import AuditEvent, FailureRecord, InvestigationReport


class OpenSearchOutcomeConflictError(RuntimeError):
    pass


class OpenSearchReportSink:
    def __init__(
        self,
        *,
        base_url: str,
        index: str,
        username: str,
        password: str,
        audit: AuditLog,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 1048576,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.index = index
        self.audit = audit
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

    def _audit(self, alert_id: str, action: str, stage: str, parameters: dict, operation_id: str) -> None:
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

    def _envelope(self, value: InvestigationReport | FailureRecord, kind: str) -> dict:
        return {
            "kind": kind,
            "alert_id": value.alert_id,
            "timestamp": value.timestamp.isoformat(),
            "payload": value.model_dump(mode="json"),
        }

    def _write(self, value: InvestigationReport | FailureRecord, kind: str) -> None:
        operation_id = str(uuid4())
        action = "report_write" if kind == "report" else "failure_write"
        envelope = self._envelope(value, kind)
        payload_json = json.dumps(envelope, sort_keys=True)
        parameters = {
            "sink": "opensearch",
            "index": self.index,
            "kind": kind,
            "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(),
        }
        self._audit(value.alert_id, action, "attempt", parameters, operation_id)
        try:
            existing = self.client.request_json("GET", f"/{self.index}/_doc/{value.alert_id}")
            if existing.status_code == 200:
                if not isinstance(existing.data, dict) or not isinstance(existing.data.get("_source"), dict):
                    raise OpenSearchRequestError("OpenSearch stored outcome is invalid")
                stored = existing.data["_source"]
                if stored != envelope:
                    raise OpenSearchOutcomeConflictError(
                        f"A different canonical outcome already exists for {value.alert_id}"
                    )
                inserted = False
            elif existing.status_code == 404:
                created = self.client.request_json(
                    "PUT",
                    f"/{self.index}/_doc/{value.alert_id}",
                    envelope,
                )
                if created.status_code not in {200, 201}:
                    raise OpenSearchRequestError(
                        f"OpenSearch returned HTTP {created.status_code} while writing outcome"
                    )
                inserted = True
            else:
                raise OpenSearchRequestError(
                    f"OpenSearch returned HTTP {existing.status_code} while reading outcome"
                )
        except Exception as exc:
            self._audit(
                value.alert_id,
                action,
                "error",
                {**parameters, "error_type": type(exc).__name__},
                operation_id,
            )
            raise
        self._audit(
            value.alert_id,
            action,
            "success",
            {**parameters, "inserted": inserted},
            operation_id,
        )

    def write(self, report: InvestigationReport) -> None:
        self._write(report, "report")

    def write_failure(self, failure: FailureRecord) -> None:
        self._write(failure, "failure")

    def get_outcome(self, alert_id: str) -> InvestigationReport | FailureRecord | None:
        response = self.client.request_json("GET", f"/{self.index}/_doc/{alert_id}")
        if response.status_code == 404:
            return None
        if response.status_code != 200 or not isinstance(response.data, dict):
            raise OpenSearchRequestError(
                f"OpenSearch returned HTTP {response.status_code} while reading outcome"
            )
        source = response.data.get("_source")
        if not isinstance(source, dict):
            raise OpenSearchRequestError("OpenSearch stored outcome is invalid")
        kind = source.get("kind")
        payload = source.get("payload")
        if kind == "report" and isinstance(payload, dict):
            return InvestigationReport.model_validate(payload)
        if kind == "failure" and isinstance(payload, dict):
            return FailureRecord.model_validate(payload)
        raise OpenSearchRequestError("OpenSearch stored outcome is invalid")
