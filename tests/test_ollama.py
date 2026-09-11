import json

import httpx
import pytest

from network_dork.adapters.llm.ollama import OllamaClient, OllamaError
from network_dork.config import LocalEndpointError

MODEL = "qwen2.5:3b-instruct"

def envelope(content='{"not": "validated here"}'):
    return {
        "model": MODEL,
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": content},
    }

def client(handler, **overrides):
    options = {
        "base_url": "http://localhost:11434",
        "model": MODEL,
        "temperature": 0.0,
        "timeout_seconds": 12,
        "transport": httpx.MockTransport(handler),
    }
    options.update(overrides)
    return OllamaClient(**options)

def test_request_uses_ollama_schema_and_configured_parameters(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://8.8.8.8:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://8.8.8.8:9999")
    seen = []

    def handler(request):
        seen.append(request)
        payload = json.loads(request.content)
        assert request.url == httpx.URL(
            "http://127.0.0.1:11434/api/chat"
        )
        assert request.headers["Host"] == "localhost:11434"
        assert payload["model"] == MODEL
        assert payload["stream"] is False
        assert payload["options"] == {
            "temperature": 0.25,
            "num_ctx": 4096,
            "num_predict": 1024,
        }
        assert payload["format"]["type"] == "object"
        assert "mitre_technique" in payload["format"]["required"]
        assert payload["messages"] == [
            {"role": "system", "content": "system text"},
            {"role": "user", "content": "user text"},
        ]
        assert request.extensions["timeout"]["read"] == 12
        return httpx.Response(200, json=envelope("unchanged output"))

    llm = client(
        handler,
        temperature=0.25,
        num_ctx=4096,
        num_predict=1024,
    )
    try:
        assert llm.complete("system text", "user text") == "unchanged output"
    finally:
        llm.close()
    assert len(seen) == 1

def test_public_endpoint_rejected_before_transport():
    def handler(request):
        raise AssertionError("Transport should not be reached")

    with pytest.raises(LocalEndpointError):
        client(handler, base_url="http://8.8.8.8:11434")

def test_redirect_is_not_followed():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            302, headers={"Location": "https://8.8.8.8/api/chat"}
        )

    llm = client(handler)
    try:
        with pytest.raises(OllamaError, match="redirect refused"):
            llm.complete("system", "user")
    finally:
        llm.close()
    assert len(seen) == 1

@pytest.mark.parametrize("status", [401, 404, 429, 500])
def test_http_errors_do_not_expose_server_body(status):
    llm = client(
        lambda request: httpx.Response(
            status, text="server body containing sensitive information"
        )
    )
    try:
        with pytest.raises(OllamaError) as caught:
            llm.complete("system", "user")
        assert str(status) in str(caught.value)
        assert "sensitive" not in str(caught.value)
    finally:
        llm.close()

@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"error": "server-side details"},
        {**envelope(), "done": False},
        {**envelope(), "done_reason": "length"},
        {**envelope(), "model": "different-model"},
        {**envelope(), "message": {"role": "user", "content": "text"}},
        {**envelope(), "message": {"role": "assistant", "content": ""}},
        {**envelope(), "message": {"role": "assistant", "content": 3}},
    ],
)
def test_invalid_envelopes_fail(payload):
    llm = client(lambda request: httpx.Response(200, json=payload))
    try:
        with pytest.raises(OllamaError):
            llm.complete("system", "user")
    finally:
        llm.close()

def test_invalid_envelope_json_fails():
    llm = client(
        lambda request: httpx.Response(200, content=b"{invalid")
    )
    try:
        with pytest.raises(OllamaError, match="envelope JSON"):
            llm.complete("system", "user")
    finally:
        llm.close()

def test_response_byte_limit_is_enforced():
    llm = client(
        lambda request: httpx.Response(200, json=envelope("x" * 2000)),
        max_response_bytes=100,
    )
    try:
        with pytest.raises(OllamaError, match="byte limit"):
            llm.complete("system", "user")
    finally:
        llm.close()

def test_oversized_prompt_is_rejected_not_truncated():
    def handler(request):
        raise AssertionError("Oversized prompts must not be sent")

    llm = client(handler, max_input_chars=10)
    try:
        with pytest.raises(OllamaError, match="input-character"):
            llm.complete("123456", "123456")
    finally:
        llm.close()

def test_timeout_has_no_hidden_client_retry():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("private details", request=request)

    llm = client(handler)
    try:
        with pytest.raises(OllamaError, match="timed out"):
            llm.complete("system", "user")
    finally:
        llm.close()
    assert len(calls) == 1

def test_model_metadata_is_read_only():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.url.path == "/api/tags"
        return httpx.Response(
            200,
            json={
                "models": [{
                    "name": MODEL,
                    "digest": "sha256:test-digest",
                    "modified_at": "2025-01-01T00:00:00Z",
                }]
            },
        )

    llm = client(handler)
    try:
        metadata = llm.installed_model()
        assert metadata["digest"] == "sha256:test-digest"
    finally:
        llm.close()
    assert len(calls) == 1

def test_missing_model_is_not_pulled():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"models": []})

    llm = client(handler)
    try:
        with pytest.raises(OllamaError, match="not installed"):
            llm.installed_model()
    finally:
        llm.close()
    assert calls == ["/api/tags"]
