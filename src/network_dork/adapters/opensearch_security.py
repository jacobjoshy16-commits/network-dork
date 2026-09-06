"""OpenSearch role bootstrap and read-only permission verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from network_dork.adapters.opensearch_common import OpenSearchJsonClient, OpenSearchRequestError


@dataclass(frozen=True)
class SecurityBootstrapConfig:
    telemetry_user: str
    telemetry_password: str
    report_user: str
    report_password: str
    telemetry_indexes: list[str]
    report_index: str


class OpenSearchSecurityBootstrapper:
    def __init__(
        self,
        *,
        base_url: str,
        admin_username: str,
        admin_password: str,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 1048576,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.client = OpenSearchJsonClient(
            base_url=base_url,
            username=admin_username,
            password=admin_password,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

    def _put(self, path: str, payload: dict[str, Any]) -> None:
        response = self.client.request_json("PUT", path, payload)
        if response.status_code not in {200, 201}:
            raise OpenSearchRequestError(
                f"OpenSearch returned HTTP {response.status_code} for security bootstrap"
            )

    def bootstrap(self, config: SecurityBootstrapConfig) -> None:
        telemetry_role = {
            "cluster_permissions": ["cluster_composite_ops_ro"],
            "index_permissions": [
                {
                    "index_patterns": config.telemetry_indexes,
                    "allowed_actions": [
                        "read",
                        "search",
                        "indices:data/read/*",
                    ],
                }
            ],
        }
        report_role = {
            "cluster_permissions": ["cluster_composite_ops"],
            "index_permissions": [
                {
                    "index_patterns": [config.report_index],
                    "allowed_actions": [
                        "crud",
                        "create_index",
                        "indices:data/write/*",
                        "indices:data/read/*",
                    ],
                }
            ],
        }
        self._put(
            "/_plugins/_security/api/roles/network_dork_telemetry_reader",
            telemetry_role,
        )
        self._put(
            "/_plugins/_security/api/roles/network_dork_report_writer",
            report_role,
        )
        self._put(
            f"/_plugins/_security/api/internalusers/{config.telemetry_user}",
            {"password": config.telemetry_password},
        )
        self._put(
            f"/_plugins/_security/api/internalusers/{config.report_user}",
            {"password": config.report_password},
        )
        self._put(
            "/_plugins/_security/api/rolesmapping/network_dork_telemetry_reader",
            {"users": [config.telemetry_user]},
        )
        self._put(
            "/_plugins/_security/api/rolesmapping/network_dork_report_writer",
            {"users": [config.report_user]},
        )
        self._put(f"/{config.report_index}", {"settings": {"number_of_shards": 1}})


def verify_read_credential_cannot_write(
    *,
    base_url: str,
    report_index: str,
    username: str,
    password: str,
    timeout_seconds: float = 30.0,
    max_response_bytes: int = 1048576,
    transport: httpx.BaseTransport | None = None,
) -> None:
    client = OpenSearchJsonClient(
        base_url=base_url,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        transport=transport,
    )
    try:
        response = client.request_json(
            "PUT",
            f"/{report_index}/_doc/network-dork-read-only-probe",
            {"probe": True},
        )
    finally:
        client.close()
    if response.status_code in {401, 403}:
        return
    raise PermissionError(
        "Telemetry credential unexpectedly wrote to the report index"
    )
