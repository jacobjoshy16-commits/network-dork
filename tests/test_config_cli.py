"""The `config` and `config-env` commands.

Configuring this involves a YAML file, an optional override, and around
seventy environment variables. These two commands are what make that
answerable without reading config.py.
"""

from typer.testing import CliRunner

from network_dork.__main__ import app


def invoke(args, env=None):
    return CliRunner().invoke(app, args, env=env or {})


def test_config_reports_nothing_changed_on_a_clean_checkout():
    result = invoke(["config", "--changed"])

    assert result.exit_code == 0
    assert "shipped default" in result.stdout


def test_config_names_the_variable_that_changed_a_setting():
    result = invoke(
        ["config", "--changed"],
        env={"NETWORK_DORK_MODEL": "qwen2.5:7b-instruct"},
    )

    assert result.exit_code == 0
    assert "qwen2.5:7b-instruct" in result.stdout
    assert "NETWORK_DORK_MODEL" in result.stdout


def test_config_shows_unchanged_settings_too_without_the_flag():
    result = invoke(["config", "--section", "llm"])

    assert result.exit_code == 0
    assert "num_ctx" in result.stdout
    assert "24576" in result.stdout


def test_config_never_prints_a_password():
    """This output is meant to be pasteable into a ticket."""
    result = invoke(
        ["config", "--section", "credentials"],
        env={
            "NETWORK_DORK_TELEMETRY_USERNAME": "ro",
            "NETWORK_DORK_TELEMETRY_PASSWORD": "hunter2",
            "NETWORK_DORK_REPORT_USERNAME": "rw",
            "NETWORK_DORK_REPORT_PASSWORD": "s3cret",
        },
    )

    assert result.exit_code == 0
    assert "hunter2" not in result.stdout
    assert "s3cret" not in result.stdout
    assert "<set>" in result.stdout


def test_config_rejects_an_unknown_section():
    result = invoke(["config", "--section", "nonexistent"])

    assert result.exit_code != 0


def test_config_fails_loudly_on_an_unloadable_configuration(tmp_path):
    """It validates as a side effect: if it prints, the settings load."""
    broken = tmp_path / "broken.yaml"
    broken.write_text("llm:\n  num_ctx: 999999999\n")

    result = invoke(["config", "--config", str(broken)])

    assert result.exit_code == 1
    assert "not loadable" in result.stdout + result.stderr


def test_config_env_lists_the_variable_for_each_setting():
    result = invoke(["config-env", "--section", "llm"])

    assert result.exit_code == 0
    assert "NETWORK_DORK_NUM_CTX" in result.stdout
    assert "NETWORK_DORK_MODEL" in result.stdout
    # Scoped: another section's variables must not appear.
    assert "NETWORK_DORK_AGENT_NAME" not in result.stdout
