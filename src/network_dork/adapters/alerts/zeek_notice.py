"""Parse existing Zeek notice records into normalized Alert models."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from network_dork.adapters.identity import normalize_alert_id
from network_dork.models import Alert


def _domains(event: dict[str, Any]) -> list[str]:
    values = [event.get("sub"), event.get("dns", {}).get("query")]
    domains: list[str] = []
    for value in values:
        if isinstance(value, str) and "." in value and value not in domains:
            domains.append(value)
    return domains


class ZeekNoticeAlertSource:
    def __init__(self, path: str | Path, source_name: str = "zeek-notice") -> None:
        self.path = Path(path)
        self.source_name = source_name

    def poll(self) -> Iterable[Alert]:
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{self.path}:{line_number}: invalid JSON") from exc
                if not isinstance(event, dict):
                    raise ValueError(f"{self.path}:{line_number}: event must be an object")
                if "note" not in event:
                    continue
                alert_id = normalize_alert_id(
                    self.source_name,
                    event.get("uid") or f"line-{line_number}",
                )
                payload = {
                    "source": self.source_name,
                    "alert_id": alert_id,
                    "timestamp": event["ts"],
                    "title": event.get("note") or "Zeek notice",
                    "description": event.get("msg") or "",
                    "src_ip": event.get("src") or event.get("id.orig_h"),
                    "dst_ip": event.get("dst") or event.get("id.resp_h"),
                    "host": event.get("host"),
                    "domains": _domains(event),
                    "original": event,
                }
                try:
                    yield Alert.model_validate(payload)
                except (ValidationError, KeyError) as exc:
                    raise ValueError(
                        f"{self.path}:{line_number}: invalid Zeek notice event"
                    ) from exc
