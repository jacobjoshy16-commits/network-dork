import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import threading

from typer.testing import CliRunner

import network_dork.__main__ as cli


class OllamaLikeHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path != "/api/tags":
            self.send_error(404)
            return
        payload = {
            "models": [
                {
                    "name": "qwen2.5:3b-instruct",
                    "digest": "sha256:e2e-test",
                    "modified_at": "2025-01-01T00:00:00Z",
                }
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        if self.path != "/api/chat":
            self.send_error(404)
            return
        length = int(self.headers["Content-Length"])
        request = json.loads(self.rfile.read(length))
        user_message = next(
            message["content"]
            for message in request["messages"]
            if message["role"] == "user"
        )
        prompt = json.loads(user_message)
        identity = prompt["required_identity"]
        alert_id = identity["alert_id"]
        report = {
            "alert_id": alert_id,
            "timestamp": identity["timestamp"],
            "summary": f"Synthetic end-to-end report for {alert_id}.",
            "mitre_technique": None,
            "nist_control": None,
            "confidence": "low",
            "context_used": [f"alert:{alert_id}"],
            "suggested_next_step": "A human analyst should review the supplied evidence.",
            "model_version": identity["model_version"],
        }
        payload = {
            "model": request["model"],
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(report)},
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def clean_environment(monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith("NETWORK_DORK_"):
            monkeypatch.delenv(name)


def test_demo_runs_end_to_end_against_local_http_server(tmp_path, monkeypatch):
    clean_environment(monkeypatch)
    server = ThreadingHTTPServer(("127.0.0.1", 0), OllamaLikeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv(
            "NETWORK_DORK_OLLAMA_BASE_URL",
            f"http://127.0.0.1:{server.server_port}",
        )
        destination = tmp_path / "demo"
        result = CliRunner().invoke(
            cli.app,
            ["demo", "--output-dir", str(destination)],
        )
        assert result.exit_code == 0, result.output
        manifest = json.loads((destination / "manifest.json").read_text())
        assert manifest["status"] == "completed"
        assert manifest["outcomes"] == 12
        assert manifest["failures"] == 0
        with sqlite3.connect(destination / "reports.sqlite3") as connection:
            assert connection.execute(
                "SELECT count(*) FROM reports"
            ).fetchone()[0] == 12
        assert Path(destination / "audit.jsonl").exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
