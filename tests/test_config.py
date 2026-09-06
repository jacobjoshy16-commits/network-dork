import pytest
from pydantic import ValidationError

from network_dork.config import load_config

def test_defaults():
    settings = load_config(environ={})
    assert settings.context.window_days == 7
    assert settings.llm.model == "qwen2.5:3b-instruct"

def test_yaml_then_environment(tmp_path):
    overlay = tmp_path / "override.yaml"
    overlay.write_text("llm:\n  model: yaml-model\n  temperature: 0.3\n")
    settings = load_config(
        overlay,
        environ={"NETWORK_DORK_MODEL": "qwen2.5:7b-instruct"},
    )
    assert settings.llm.model == "qwen2.5:7b-instruct"
    assert settings.llm.temperature == 0.3
    assert settings.context.window_days == 7

def test_environment_selects_yaml(tmp_path):
    overlay = tmp_path / "override.yaml"
    overlay.write_text("context:\n  window_days: 4\n")
    settings = load_config(environ={"NETWORK_DORK_CONFIG": str(overlay)})
    assert settings.context.window_days == 4

def test_invalid_environment_value():
    with pytest.raises(ValidationError):
        load_config(environ={"NETWORK_DORK_MAX_ATTEMPTS": "0"})

def test_unknown_yaml_field_fails(tmp_path):
    overlay = tmp_path / "override.yaml"
    overlay.write_text("llm:\n  temprature: 0.5\n")
    with pytest.raises(ValidationError):
        load_config(overlay, environ={})

def test_credential_identity_reuse_is_rejected():
    with pytest.raises(ValidationError):
        load_config(
            environ={
                "NETWORK_DORK_TELEMETRY_USERNAME": "shared",
                "NETWORK_DORK_TELEMETRY_PASSWORD": "read-secret",
                "NETWORK_DORK_REPORT_USERNAME": "shared",
                "NETWORK_DORK_REPORT_PASSWORD": "write-secret",
            }
        )

def test_credential_secret_is_not_in_repr():
    settings = load_config(
        environ={
            "NETWORK_DORK_TELEMETRY_USERNAME": "reader",
            "NETWORK_DORK_TELEMETRY_PASSWORD": "a-sensitive-password",
        }
    )
    assert "a-sensitive-password" not in repr(settings)

def test_yaml_requires_mapping(tmp_path):
    overlay = tmp_path / "override.yaml"
    overlay.write_text("- not\n- a\n- mapping\n")
    with pytest.raises(ValueError, match="mapping"):
        load_config(overlay, environ={})
