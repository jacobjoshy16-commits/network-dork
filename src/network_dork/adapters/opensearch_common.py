"""Shared OpenSearch transport helpers.

These helpers enforce the same local/LAN-only runtime constraints as the
Ollama adapter. They never perform DNS resolution, follow redirects, or use
proxy environment variables.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

import httpx

from network_dork.config import resolve_local_endpoint


class OpenSearchRequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class OpenSearchResponse:
    status_code: int
    data: object | None


class OpenSearchJsonClient:
    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        timeout_seconds: float,
        max_response_bytes: int = 1048576,
        allow_plaintext: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not username or not password:
            raise ValueError("OpenSearch username and password are required")
        if timeout_seconds <= 0:
            raise ValueError("OpenSearch timeout must be positive")
        if max_response_bytes < 1:
            raise ValueError("OpenSearch response bound must be positive")

        endpoint = resolve_local_endpoint(
            base_url, allow_plaintext=allow_plaintext
        )
        self._server_hostname = endpoint.server_hostname
        self.max_response_bytes = max_response_bytes
        self._client = httpx.Client(
            base_url=endpoint.connect_url,
            headers={
                "Host": endpoint.host_header,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            auth=(username, password),
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            verify=True,
            transport=transport,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        )

    def close(self) -> None:
        self._client.close()

    def request_json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> OpenSearchResponse:
        try:
            with self._client.stream(
                method,
                path,
                json=payload,
                extensions={"sni_hostname": self._server_hostname},
            ) as response:
                if 300 <= response.status_code < 400:
                    raise OpenSearchRequestError("OpenSearch redirect refused")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise OpenSearchRequestError(
                            "OpenSearch response exceeded configured byte limit"
                        )
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise OpenSearchRequestError("OpenSearch request timed out") from exc
        except httpx.HTTPError as exc:
            raise OpenSearchRequestError("OpenSearch transport request failed") from exc

        body = b"".join(chunks)
        if not body:
            return OpenSearchResponse(response.status_code, None)
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError) as exc:
            raise OpenSearchRequestError("OpenSearch returned invalid JSON") from exc
        return OpenSearchResponse(response.status_code, data)
