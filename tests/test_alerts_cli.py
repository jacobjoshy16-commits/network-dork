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


def test_every_command_can_print_its_help():
    """typer 0.15.2 calls click's Parameter.make_metavar() without a ctx,
    which click 8.2 made required, so a transitive click bump broke --help on
    every command at once and nothing noticed. pyproject pins click below
    that; this fails if the pin is lost."""
    listed = invoke(["--help"])
    assert listed.exit_code == 0

    names = [
        "adapters", "alerts", "preflight", "trace", "readiness",
        "verify-audit", "agent", "context", "config", "config-env",
        "eval-reports", "eval", "run", "demo",
    ]
    for name in names:
        result = invoke([name, "--help"])
        assert result.exit_code == 0, f"{name} --help: {result.output}"


def test_readiness_can_assess_a_window_it_is_pointed_at():
    """Without --as-of the window ends now, so a stored capture reports no
    hosts however much history it holds -- none of it lands in the window."""
    result = invoke(["readiness", *CONFIG, "--as-of", "2025-01-15T12:00:00Z"])

    assert result.exit_code == 0
    assert "hosts have enough history" in result.stdout
    assert "10.77.0.1" in result.stdout


def test_readiness_rejects_an_unparseable_as_of():
    result = invoke(["readiness", *CONFIG, "--as-of", "last tuesday"])

    assert result.exit_code != 0
    assert "ISO-8601" in result.output


def test_no_file_alert_adapter_hardcodes_a_path():
    """NETWORK_DORK_ALERTS_PATH is documented as the knob that says where
    alerts come from, and suricata_eve and zeek_notice used to hardcode the
    bundled samples instead. Pointing the tool at a real eve.json therefore
    returned two fixture alerts from January 2025, with no error and nothing
    to suggest the path had been ignored.

    Interpolation happens when an adapter is built, so at this layer the
    check is that each one defers to the setting rather than naming a file.
    """
    from network_dork.config import load_config

    settings = load_config(None)
    for name in ("file", "suricata_eve", "zeek_notice"):
        path = settings.adapters["alerts"][name].options["path"]
        assert path == "${alerts.path}", f"{name} hardcodes {path!r}"


def test_alerts_reads_the_path_it_is_pointed_at(tmp_path):
    """The end-to-end version of the above, through the CLI."""
    eve = tmp_path / "eve.json"
    eve.write_text(
        json.dumps(
            {
                "event_type": "alert",
                "flow_id": 7,
                "timestamp": "2026-09-11T19:13:13.503356-0500",
                "src_ip": "10.1.2.3",
                "dest_ip": "203.0.113.9",
                "alert": {
                    "signature": "ET INFO from the real capture",
                    "signature_id": 2071408,
                    "category": "Not Suspicious Traffic",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = invoke(
        ["alerts", *CONFIG],
        env={
            "NETWORK_DORK_ALERT_ADAPTER": "suricata_eve",
            "NETWORK_DORK_ALERTS_PATH": str(eve),
        },
    )

    assert result.exit_code == 0
    assert "ET INFO from the real capture" in result.stdout
    # Not the bundled sample, which is what used to come back.
    assert "10.10.1.5" not in result.stdout
