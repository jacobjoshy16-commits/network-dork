"""Read OpenSearch alert search results or query OpenSearch directly."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from network_dork.adapters.opensearch_common import OpenSearchJsonClient, OpenSearchRequestError
from network_dork.adapters.identity import normalize_alert_id
from network_dork.models import Alert


def _get_path(document: dict[str, Any], dotted: str) -> Any:
    current: Any = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _pick(document: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _get_path(document, path)
        if value not in (None, ""):
            return value
    return None


def _collect_domains(document: dict[str, Any]) -> list[str]:
    candidates = [
        _pick(document, "dns.question.name", "dns.rrname"),
        _pick(document, "url.domain", "destination.domain"),
        _pick(document, "suricata.eve.http.hostname", "suricata.eve.tls.sni"),
    ]
    domains: list[str] = []
    for value in candidates:
        if isinstance(value, str) and value.strip() and value not in domains:
            domains.append(value)
    return domains


def _alert_from_document(
    document: dict[str, Any],
    *,
    alert_id: str,
    source_name: str,
) -> Alert:
    payload = {
        "source": source_name,
        "alert_id": alert_id,
        "timestamp": _pick(document, "@timestamp", "event.created", "timestamp"),
        "title": _pick(
            document,
            "rule.name",
            "signal.rule.name",
            "suricata.eve.alert.signature",
            "alert.signature",
            "event.action",
            "message",
        )
        or "OpenSearch alert",
        "description": _pick(
            document,
            "message",
            "suricata.eve.alert.category",
            "alert.category",
            "event.reason",
        )
        or "",
        "src_ip": _pick(document, "source.ip", "src_ip", "src.ip"),
        "dst_ip": _pick(document, "destination.ip", "dest_ip", "dst.ip"),
        "host": _pick(document, "host.name", "host.hostname"),
        "domains": _collect_domains(document),
        "original": document,
    }
    return Alert.model_validate(payload)


def _iter_export_records(path: Path) -> Iterable[tuple[str, dict[str, Any]]]:
    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()
    if not stripped:
        return
    if stripped[0] in "[{":
        value = json.loads(stripped)
        if isinstance(value, dict) and isinstance(value.get("hits"), dict):
            hits = value["hits"].get("hits")
            if not isinstance(hits, list):
                raise ValueError(f"{path}: search response missing hits.hits list")
            for item in hits:
                if not isinstance(item, dict):
                    raise ValueError(f"{path}: hit must be an object")
                if isinstance(item.get("_source"), dict):
                    yield str(item.get("_id") or "no-id"), item["_source"]
                else:
                    yield str(item.get("_id") or "no-id"), item
            return
        if isinstance(value, list):
            for index, item in enumerate(value, start=1):
                if not isinstance(item, dict):
                    raise ValueError(f"{path}: list item {index} must be an object")
                if isinstance(item.get("_source"), dict):
                    yield str(item.get("_id") or f"item-{index}"), item["_source"]
                else:
                    yield str(item.get("_id") or f"item-{index}"), item
            return
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f"{path}:{line_number}: record must be an object")
        if isinstance(item.get("_source"), dict):
            yield str(item.get("_id") or f"line-{line_number}"), item["_source"]
        else:
            yield str(item.get("_id") or f"line-{line_number}"), item


class OpenSearchAlertSource:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        base_url: str | None = None,
        index: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: float = 30.0,
        max_hits: int = 100,
        max_response_bytes: int = 1048576,
        source_name: str = "opensearch-alerts",
        transport: httpx.BaseTransport | None = None,
        query: dict[str, Any] | None = None,
    ) -> None:
        self.path = None if path is None else Path(path)
        self.index = index
        self.max_hits = max_hits
        self.source_name = source_name
        self.query = query
        self._client: OpenSearchJsonClient | None = None
        if self.path is None:
            if not all([base_url, index, username, password]):
                raise ValueError(
                    "OpenSearchAlertSource requires either path or live connection settings"
                )
            self._client = OpenSearchJsonClient(
                base_url=base_url,
                username=username,
                password=password,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
                transport=transport,
            )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def _from_file(self) -> Iterable[Alert]:
        assert self.path is not None
        for hit_id, document in _iter_export_records(self.path):
            try:
                yield _alert_from_document(
                    document,
                    alert_id=normalize_alert_id(self.source_name, hit_id),
                    source_name=self.source_name,
                )
            except ValidationError as exc:
                raise ValueError(f"{self.path}: invalid OpenSearch alert document") from exc

    def _from_live(self) -> Iterable[Alert]:
        assert self._client is not None
        assert self.index is not None
        body = self.query or {"size": self.max_hits, "query": {"match_all": {}}}
        response = self._client.request_json("POST", f"/{self.index}/_search", body)
        if response.status_code != 200 or not isinstance(response.data, dict):
            raise OpenSearchRequestError(
                f"OpenSearch returned HTTP {response.status_code} for alert search"
            )
        hits = response.data.get("hits", {}).get("hits")
        if not isinstance(hits, list):
            raise OpenSearchRequestError("OpenSearch alert search response is invalid")
        for item in hits:
            if not isinstance(item, dict) or not isinstance(item.get("_source"), dict):
                raise OpenSearchRequestError("OpenSearch alert hit is invalid")
            try:
                yield _alert_from_document(
                    item["_source"],
                    alert_id=normalize_alert_id(
                        self.source_name, item.get("_id", "no-id")
                    ),
                    source_name=self.source_name,
                )
            except ValidationError as exc:
                raise OpenSearchRequestError("OpenSearch alert document is invalid") from exc

    def poll(self) -> Iterable[Alert]:
        if self.path is not None:
            yield from self._from_file()
            return
        yield from self._from_live()
