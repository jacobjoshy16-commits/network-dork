"""The `alerts` command.

Every command that acts on one alert needs its identifier, and identifiers
are normalized from whatever the sensor called it -- a Suricata id is built
from the flow id, signature id and line number and appears nowhere in
eve.json. Without this command, finding one means reimplementing the adapter
at the shell, which is not something an operator should be asked to do.
"""

import json

from typer.testing import CliRunner

from network_dork.__main__ import app

CONFIG = ["--config", "config/default.yaml"]


def invoke(args, env=None):
    return CliRunner().invoke(app, args, env=env or {})


def test_alerts_lists_identifiers_usable_with_trace():
    result = invoke(["alerts", *CONFIG])

    assert result.exit_code == 0
    assert "syn-001" in result.stdout
    # The id has to be usable as-is, so it is printed alone on its line.
    assert any(
        line.strip() == "syn-001" for line in result.stdout.splitlines()
    )


def test_alerts_groups_by_title_before_listing():
    """A real capture is mostly one or two repeating signatures, so the
    decision is which kind to investigate, not which instance."""
    result = invoke(["alerts", *CONFIG])

    assert "12 alert(s) by title:" in result.stdout
    titles = result.stdout.index("by title:")
    identifiers = result.stdout.index("identifiers for --alert-id")
    assert titles < identifiers


def test_match_narrows_by_title():
    result = invoke(["alerts", *CONFIG, "--match", "TXT"])

    assert result.exit_code == 0
    assert "syn-004" in result.stdout
    assert "syn-001" not in result.stdout


def test_limit_truncates_and_says_how_many_remain():
    result = invoke(["alerts", *CONFIG, "--limit", "3"])

    assert "(3 of 12)" in result.stdout
    assert "9 more" in result.stdout


def test_limit_zero_lists_everything():
    result = invoke(["alerts", *CONFIG, "--limit", "0"])

    assert "(12 of 12)" in result.stdout
    assert "more. Use --limit 0" not in result.stdout


def test_json_output_is_machine_readable():
    result = invoke(["alerts", *CONFIG, "--json", "--match", "TXT"])

    payload = json.loads(result.stdout)
    assert len(payload) == 1
    assert payload[0]["alert_id"] == "syn-004"
    assert payload[0]["src_ip"] == "10.77.0.4"


def test_no_matches_says_so_rather_than_printing_an_empty_table():
    result = invoke(["alerts", *CONFIG, "--match", "no-such-signature"])

    assert result.exit_code == 0
    assert "No alerts in the configured source" in result.stdout
    assert "no-such-signature" in result.stdout
