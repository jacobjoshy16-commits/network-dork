import pytest
from pydantic import ValidationError

from network_dork.config import (
    ENV_PATHS,
    env_variable_for,
    explain,
    load_config,
)


def test_defaults():
    settings = load_config(environ={})
    assert settings.context.window_days == 7
    assert settings.llm.model == "qwen2.5:3b-instruct"
    assert settings.opensearch.reports_index == "network-dork-reports"


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


def test_opensearch_environment_overrides():
    settings = load_config(
        environ={
            "NETWORK_DORK_OPENSEARCH_BASE_URL": "http://127.0.0.1:9201",
            "NETWORK_DORK_OPENSEARCH_MAX_HITS": "250",
        }
    )
    assert settings.opensearch.base_url == "http://127.0.0.1:9201"
    assert settings.opensearch.max_hits == 250


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


# --- provenance -------------------------------------------------------------


def origin_for(origins, section, key):
    for item in origins:
        if item.section == section and item.key == key:
            return item
    raise AssertionError(f"No origin recorded for {section}.{key}")


def test_explain_agrees_with_load_config():
    """A provenance report derived from a second code path would drift.

    If these two ever disagree, the report is describing a configuration
    nobody is running.
    """
    environ = {"NETWORK_DORK_MODEL": "qwen2.5:7b-instruct"}
    settings, origins = explain(environ=environ)

    assert settings.model_dump(mode="json") == load_config(
        environ=environ
    ).model_dump(mode="json")
    for item in origins:
        section = getattr(settings, item.section)
        assert section.model_dump(mode="json")[item.key] == item.value


def test_the_shipped_file_counts_as_a_default_not_an_override():
    """config/default.yaml restates the field defaults.

    Labelling those as overrides would flag every setting and bury the two
    an operator actually changed.
    """
    _, origins = explain(environ={})

    assert all(item.from_default for item in origins)


def test_an_environment_variable_is_named_as_the_source():
    _, origins = explain(environ={"NETWORK_DORK_MODEL": "qwen2.5:7b-instruct"})

    model = origin_for(origins, "llm", "model")
    assert model.value == "qwen2.5:7b-instruct"
    assert model.source == "NETWORK_DORK_MODEL"
    assert not model.from_default
    # Its neighbours must not be dragged along.
    assert origin_for(origins, "llm", "num_ctx").from_default


def test_an_override_file_is_named_as_the_source(tmp_path):
    overlay = tmp_path / "override.yaml"
    overlay.write_text("context:\n  window_days: 4\n")

    _, origins = explain(overlay, environ={})

    window = origin_for(origins, "context", "window_days")
    assert window.value == 4
    assert window.source == str(overlay)


def test_the_last_layer_wins_and_is_the_one_reported(tmp_path):
    """An operator who sets a value in YAML and again in the environment
    needs to be told which one the run is using."""
    overlay = tmp_path / "override.yaml"
    overlay.write_text("llm:\n  model: from-yaml\n")

    _, origins = explain(
        overlay, environ={"NETWORK_DORK_MODEL": "from-env"}
    )

    model = origin_for(origins, "llm", "model")
    assert model.value == "from-env"
    assert model.source == "NETWORK_DORK_MODEL"


def test_secrets_are_flagged_for_redaction():
    _, origins = explain(
        environ={
            "NETWORK_DORK_TELEMETRY_USERNAME": "ro",
            "NETWORK_DORK_TELEMETRY_PASSWORD": "hunter2",
            "NETWORK_DORK_REPORT_USERNAME": "rw",
            "NETWORK_DORK_REPORT_PASSWORD": "s3cret",
        }
    )

    assert origin_for(origins, "credentials", "telemetry_password").redacted
    assert not origin_for(origins, "credentials", "telemetry_username").redacted


def test_no_secret_value_survives_into_a_provenance_report():
    """The report is meant to be pasted into a ticket."""
    _, origins = explain(
        environ={
            "NETWORK_DORK_TELEMETRY_USERNAME": "ro",
            "NETWORK_DORK_TELEMETRY_PASSWORD": "hunter2",
            "NETWORK_DORK_REPORT_USERNAME": "rw",
            "NETWORK_DORK_REPORT_PASSWORD": "s3cret",
        }
    )

    rendered = " ".join(str(item.value) for item in origins)
    assert "hunter2" not in rendered
    assert "s3cret" not in rendered


def test_every_environment_variable_names_a_real_setting():
    """A typo in ENV_PATHS would silently create a variable that does
    nothing, and nothing else would catch it."""
    settings = load_config(environ={})

    for variable, (section, key) in ENV_PATHS.items():
        assert hasattr(settings, section), f"{variable} -> unknown {section}"
        fields = type(getattr(settings, section)).model_fields
        assert key in fields, f"{variable} -> {section} has no field {key}"


def test_the_variable_for_a_setting_is_discoverable():
    assert env_variable_for("llm", "model") == "NETWORK_DORK_MODEL"
    assert env_variable_for("llm", "nonexistent") is None
