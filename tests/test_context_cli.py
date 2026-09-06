import json

from typer.testing import CliRunner

from network_dork.__main__ import app

def test_context_command_prints_fixture_evidence(tmp_path, monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith("NETWORK_DORK_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv(
        "NETWORK_DORK_AUDIT_PATH", str(tmp_path / "audit.jsonl")
    )
    result = CliRunner().invoke(
        app, ["context", "--alert-id", "syn-001"]
    )
    assert result.exit_code == 0, result.output
    context = json.loads(result.stdout)
    assert context["alert"]["alert_id"] == "syn-001"
    assert len(context["flows"]) == 3
    assert len(context["dns"]) == 1
    assert len(context["auth"]) == 1
