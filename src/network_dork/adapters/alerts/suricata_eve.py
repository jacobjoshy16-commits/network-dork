"""Parse existing Suricata EVE alerts into normalized Alert models."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from network_dork.models import Alert


def _collect_domains(event: dict[str, Any]) -> list[str]:
    values = [
        event.get("http", {}).get("hostname"),
        event.get("dns", {}).get("rrname"),
        event.get("tls", {}).get("sni"),
    ]
    domains: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip() and value not in domains:
            domains.append(value)
    return domains


class SuricataEveAlertSource:
    def __init__(self, path: str | Path, source_name: str = "suricata-eve") -> None:
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
                if event.get("event_type") != "alert":
                    continue
                alert_block = event.get("alert")
                if not isinstance(alert_block, dict):
                    raise ValueError(f"{self.path}:{line_number}: alert event missing alert object")
                alert_id = (
                    f"{self.source_name}:"
                    f"{event.get('flow_id', 'no-flow')}:"
                    f"{alert_block.get('signature_id', 'no-sid')}:"
                    f"{line_number}"
                )
                payload = {
                    "source": self.source_name,
                    "alert_id": alert_id,
                    "timestamp": event["timestamp"],
                    "title": alert_block.get("signature") or "Suricata alert",
                    "description": alert_block.get("category") or event.get("app_proto") or "",
                    "src_ip": event.get("src_ip"),
                    "dst_ip": event.get("dest_ip"),
                    "host": event.get("host"),
                    "domains": _collect_domains(event),
                    "original": event,
                }
                try:
                    yield Alert.model_validate(payload)
                except (ValidationError, KeyError) as exc:
                    raise ValueError(
                        f"{self.path}:{line_number}: invalid Suricata alert event"
                    ) from exc
