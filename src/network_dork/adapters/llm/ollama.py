"""Ollama-only inference over a pinned local/LAN HTTP connection.

Does not pull models, follow redirects, use proxies, call external APIs,
or silently replace an unavailable model with a fake.
"""

from __future__ import annotations

import json

import httpx

from network_dork.config import resolve_local_endpoint
from network_dork.models import InvestigationReport

class OllamaError(RuntimeError):
    pass

class OllamaClient:
    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        temperature: float,
        timeout_seconds: float,
        num_ctx: int = 8192,
        num_predict: int = 2048,
        max_input_chars: int = 32000,
        max_response_bytes: int = 1048576,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("Model name must not be empty")
        if not 0 <= temperature <= 2:
            raise ValueError("Temperature must be between zero and two")
        if timeout_seconds <= 0:
            raise ValueError("Timeout must be positive")
        if num_ctx < 1 or num_predict < 1:
            raise ValueError("Model context and output limits must be positive")
        if max_input_chars < 1 or max_response_bytes < 1:
            raise ValueError("Input and response bounds must be positive")

        endpoint = resolve_local_endpoint(base_url)
        self.model = model
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.max_input_chars = max_input_chars
        self.max_response_bytes = max_response_bytes
        self._server_hostname = endpoint.server_hostname
        self._client = httpx.Client(
            base_url=endpoint.connect_url,
            headers={
                "Host": endpoint.host_header,
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            verify=True,
            transport=transport,
            limits=httpx.Limits(
                max_connections=2,
                max_keepalive_connections=1,
            ),
        )

    def close(self) -> None:
        self._client.close()

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> dict:
        try:
            with self._client.stream(
                method,
                path,
                json=payload,
                extensions={"sni_hostname": self._server_hostname},
            ) as response:
                if 300 <= response.status_code < 400:
                    raise OllamaError("Ollama redirect refused")
                if response.status_code != 200:
                    # Avoid persisting arbitrary server bodies or headers.
                    raise OllamaError(
                        f"Ollama returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise OllamaError(
                            "Ollama response exceeded configured byte limit"
                        )
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise OllamaError("Ollama request timed out") from exc
        except httpx.HTTPError as exc:
            raise OllamaError("Ollama transport request failed") from exc

        try:
            result = json.loads(b"".join(chunks))
        except (ValueError, UnicodeError) as exc:
            raise OllamaError("Ollama returned invalid envelope JSON") from exc
        if not isinstance(result, dict):
            raise OllamaError("Ollama response envelope is not an object")
        if "error" in result:
            raise OllamaError("Ollama reported an inference error")
        return result

    def complete(self, system: str, user: str) -> str:
        if len(system) + len(user) > self.max_input_chars:
            # Never silently truncate evidence before investigation.
            raise OllamaError(
                "Prompt exceeds configured input-character limit"
            )
        payload = {
            "model": self.model,
            "stream": False,
            "format": InvestigationReport.model_json_schema(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
            "keep_alive": "5m",
        }
        envelope = self._request_json("POST", "/api/chat", payload)
        if envelope.get("done") is not True:
            raise OllamaError("Ollama returned an incomplete generation")
        if envelope.get("done_reason") == "length":
            raise OllamaError("Ollama generation reached its output limit")
        if envelope.get("model") != self.model:
            raise OllamaError("Ollama responded with an unexpected model name")
        message = envelope.get("message")
        if (
            not isinstance(message, dict)
            or message.get("role") != "assistant"
            or not isinstance(message.get("content"), str)
            or not message["content"].strip()
        ):
            raise OllamaError("Ollama response lacks assistant content")

        # Return exactly what the model produced. The pipeline validates
        # it; this adapter never patches report fields or strips fences.
        return message["content"]

    def installed_model(self) -> dict[str, str | None]:
        """Read local model metadata without pulling or modifying models."""
        envelope = self._request_json("GET", "/api/tags")
        models = envelope.get("models")
        if not isinstance(models, list):
            raise OllamaError("Ollama returned invalid model metadata")
        for model in models:
            if not isinstance(model, dict):
                continue
            if self.model not in {model.get("name"), model.get("model")}:
                continue
            digest = model.get("digest")
            if not isinstance(digest, str) or not digest:
                raise OllamaError("Installed model has no digest")
            return {
                "requested_model": self.model,
                "digest": digest,
                "modified_at": (
                    model["modified_at"]
                    if isinstance(model.get("modified_at"), str)
                    else None
                ),
            }
        raise OllamaError(
            "Configured model is not installed; provision it separately"
        )
