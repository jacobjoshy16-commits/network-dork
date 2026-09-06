import json

from typer.testing import CliRunner

import network_dork.__main__ as cli

def clean_environment(monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith("NETWORK_DORK_"):
            monkeypatch.delenv(name)

def test_demo_refuses_existing_output_directory(tmp_path, monkeypatch):
    clean_environment(monkeypatch)
    destination = tmp_path / "existing"
    destination.mkdir()
    marker = destination / "do-not-delete"
    marker.write_text("preserve")
    result = CliRunner().invoke(
        cli.app, ["demo", "--output-dir", str(destination)]
    )
    assert result.exit_code != 0
    assert marker.read_text() == "preserve"
    assert "refusing to overwrite" in result.output

def test_demo_records_preflight_failure_without_fake_fallback(
    tmp_path, monkeypatch
):
    clean_environment(monkeypatch)

    class UnavailableModel:
        def installed_model(self):
            raise RuntimeError("unavailable")

    class MustNotRun:
        def run_once(self):
            raise AssertionError("Pipeline must not run after failed preflight")

    def wire(settings, resources, *, fake=False):
        assert fake is False
        return MustNotRun(), UnavailableModel()

    monkeypatch.setattr(cli, "wire_pipeline", wire)
    destination = tmp_path / "demo-failed"
    result = CliRunner().invoke(
        cli.app, ["demo", "--output-dir", str(destination)]
    )
    assert result.exit_code == 1
    manifest = json.loads(
        (destination / "manifest.json").read_text()
    )
    assert manifest["status"] == "aborted"
    assert manifest["fake_model"] is False
    assert manifest["error_type"] == "RuntimeError"
    assert "No fake fallback was used" in result.output

def test_demo_uses_fresh_storage_and_does_not_read_ground_truth(
    tmp_path, monkeypatch
):
    clean_environment(monkeypatch)
    captured = {}

    class ModelMetadata:
        def installed_model(self):
            return {
                "requested_model": "qwen2.5:3b-instruct",
                "digest": "unit-test-digest",
                "modified_at": None,
            }

    class EmptyPipeline:
        def run_once(self):
            return []

    def wire(settings, resources, *, fake=False):
        assert fake is False
        captured["settings"] = settings
        return EmptyPipeline(), ModelMetadata()

    monkeypatch.setattr(cli, "wire_pipeline", wire)
    destination = tmp_path / "demo"
    result = CliRunner().invoke(
        cli.app, ["demo", "--output-dir", str(destination)]
    )
    assert result.exit_code == 0, result.output
    settings = captured["settings"]
    assert settings.storage.state_path == destination / "state.sqlite3"
    assert settings.storage.reports_path == destination / "reports.sqlite3"
    manifest = json.loads(
        (destination / "manifest.json").read_text()
    )
    assert manifest["fake_model"] is False
    assert manifest["installed_model"]["digest"] == "unit-test-digest"
    assert all(
        "ground_truth" not in name
        for name in manifest["fixtures_sha256"]
    )
