"""OpenSearch report sink with explicit failure records and idempotency."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import quote
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
        allow_plaintext: bool = False,
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
            allow_plaintext=allow_plaintext,
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

    @staticmethod
    def _document_id(source: str, alert_id: str) -> str:
        """Percent-encode the whole key so it can only be one path segment.

        Alert identifiers originate in untrusted sensor data. Without encoding,
        a native id containing "/../" rewrites the request path and turns this
        sink into an arbitrary-endpoint writer.
        """
        return quote(f"{source}:{alert_id}", safe="")

    def _envelope(
        self, source: str, value: InvestigationReport | FailureRecord, kind: str
    ) -> dict:
        return {
            "kind": kind,
            "source": source,
            "alert_id": value.alert_id,
            "timestamp": value.timestamp.isoformat(),
            "payload": value.model_dump(mode="json"),
        }

    def _write(
        self, source: str, value: InvestigationReport | FailureRecord, kind: str
    ) -> None:
        operation_id = str(uuid4())
        action = "report_write" if kind == "report" else "failure_write"
        envelope = self._envelope(source, value, kind)
        payload_json = json.dumps(envelope, sort_keys=True)
        document_id = self._document_id(source, value.alert_id)
        parameters = {
            "sink": "opensearch",
            "index": self.index,
            "source": source,
            "kind": kind,
            "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(),
        }
        self._audit(value.alert_id, action, "attempt", parameters, operation_id)
        try:
            existing = self.client.request_json("GET", f"/{self.index}/_doc/{document_id}")
            if existing.status_code == 200:
                if not isinstance(existing.data, dict) or not isinstance(existing.data.get("_source"), dict):
                    raise OpenSearchRequestError("OpenSearch stored outcome is invalid")
                stored = existing.data["_source"]
                if stored != envelope:
                    raise OpenSearchOutcomeConflictError(
                        "A different canonical outcome already exists for "
                        f"{source}/{value.alert_id}"
                    )
                inserted = False
            elif existing.status_code == 404:
                created = self.client.request_json(
                    "PUT",
                    f"/{self.index}/_doc/{document_id}",
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

    def write(self, source: str, report: InvestigationReport) -> None:
        self._write(source, report, "report")

    def write_failure(self, source: str, failure: FailureRecord) -> None:
        self._write(source, failure, "failure")

    def get_outcome(
        self, source: str, alert_id: str
    ) -> InvestigationReport | FailureRecord | None:
        document_id = self._document_id(source, alert_id)
        response = self.client.request_json("GET", f"/{self.index}/_doc/{document_id}")
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
