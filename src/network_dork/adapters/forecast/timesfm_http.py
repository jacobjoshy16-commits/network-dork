"""Client for the TimesFM forecasting sidecar.

TimesFM is a PyTorch model, not an Ollama model, so it runs as a separate
service rather than in this process. That keeps torch and the HuggingFace
stack out of the investigation runtime's dependency set, supply chain, and
SBOM, and it means the sidecar is reachable only through the same
loopback/RFC-1918 endpoint allowlist that constrains every other client here.

TimesFM forecasts. It does not detect anomalies; scoring a forecast against
observed values is network-dork's own logic in network_dork.anomaly.

Licensing: TimesFM weights up to 2.5 are Apache-2.0. The 3.0 weights are
released under a non-commercial licence that forbids production use, so the
sidecar refuses to serve them and this client refuses to accept a 3.x model
name in a response.
"""

from __future__ import annotations

import json
import re

import httpx

from network_dork.config import resolve_local_endpoint
from network_dork.models import Forecast, TimeSeries

# Weights whose licence forbids production use.
NON_COMMERCIAL_MODEL = re.compile(r"timesfm[-_]?3(\.|$|[-_])", re.IGNORECASE)


class ForecastServiceError(RuntimeError):
    pass


class TimesFMForecaster:
    name = "timesfm"

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 60.0,
        max_response_bytes: int = 4194304,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Timeout must be positive")
        if max_response_bytes < 1:
            raise ValueError("Response bound must be positive")

        endpoint = resolve_local_endpoint(base_url)
        self.max_response_bytes = max_response_bytes
        self._server_hostname = endpoint.server_hostname
        self._client = httpx.Client(
            base_url=endpoint.connect_url,
            headers={
                "Host": endpoint.host_header,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            verify=True,
            transport=transport,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
        )

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, payload: dict) -> dict:
        try:
            with self._client.stream(
                "POST",
                path,
                json=payload,
                extensions={"sni_hostname": self._server_hostname},
            ) as response:
                if 300 <= response.status_code < 400:
                    raise ForecastServiceError("Forecast redirect refused")
                if response.status_code != 200:
                    raise ForecastServiceError(
                        f"Forecast service returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise ForecastServiceError(
                            "Forecast response exceeded the configured limit"
                        )
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise ForecastServiceError("Forecast request timed out") from exc
        except httpx.HTTPError as exc:
            raise ForecastServiceError("Forecast transport failed") from exc

        try:
            envelope = json.loads(b"".join(chunks))
        except (ValueError, UnicodeError) as exc:
            raise ForecastServiceError("Forecast response is not JSON") from exc
        if not isinstance(envelope, dict):
            raise ForecastServiceError("Forecast envelope is not an object")
        return envelope

    @staticmethod
    def _floats(envelope: dict, key: str, expected: int) -> list[float]:
        values = envelope.get(key)
        if not isinstance(values, list) or len(values) != expected:
            raise ForecastServiceError(f"Forecast field {key!r} is malformed")
        result: list[float] = []
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ForecastServiceError(
                    f"Forecast field {key!r} contains a non-number"
                )
            result.append(float(value))
        return result

    def forecast(self, series: TimeSeries, horizon: int) -> Forecast:
        if horizon < 1:
            raise ValueError("horizon must be positive")
        envelope = self._post(
            "/forecast",
            {
                "values": series.values,
                "horizon": horizon,
                "bucket_seconds": series.bucket_seconds,
            },
        )

        model = envelope.get("model")
        if not isinstance(model, str) or not model.strip():
            raise ForecastServiceError("Forecast response names no model")
        if NON_COMMERCIAL_MODEL.search(model):
            raise ForecastServiceError(
                f"Refusing forecast from {model!r}: TimesFM 3.x weights are "
                "licensed for non-commercial use only"
            )

        digest = envelope.get("model_digest")
        if digest is not None and not isinstance(digest, str):
            raise ForecastServiceError("Forecast model digest is malformed")

        return Forecast(
            model=model,
            model_digest=digest,
            median=self._floats(envelope, "median", horizon),
            lower=self._floats(envelope, "lower", horizon),
            upper=self._floats(envelope, "upper", horizon),
        )
