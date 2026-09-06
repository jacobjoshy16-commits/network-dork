from pathlib import Path

import pytest
from typer.testing import CliRunner

from network_dork.__main__ import app, load_adapter
from network_dork.adapters.alerts.file import FileAlertSource

NullContextProvider = load_adapter(
    "network_dork.adapters.context.null:NullContextProvider"
)


def test_cli_lists_importable_registered_adapters(monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith("NETWORK_DORK_"):
            monkeypatch.delenv(name)
    result = CliRunner().invoke(app, ["adapters"])
    assert result.exit_code == 0, result.output
    assert "alerts\tfile\t" in result.output
    assert "alerts\tsuricata_eve\t" in result.output
    assert "alerts\tzeek_notice\t" in result.output
    assert "alerts\topensearch\t" in result.output
    assert "context\tnull\t" in result.output
    assert "context\topensearch\t" in result.output
    assert "llm\tollama\t" in result.output
    assert "sinks\topensearch\t" in result.output


def test_adapter_reference_requires_class():
    with pytest.raises(ValueError, match="module:class"):
        load_adapter("not-an-adapter-reference")
    with pytest.raises(ValueError, match="not a class"):
        load_adapter("network_dork.config:load_config")


def test_normalized_file_source_is_repeatable():
    source = FileAlertSource("fixtures/alerts/alerts.jsonl")
    first = list(source.poll())
    second = list(source.poll())
    assert len(first) == 12
    assert first == second


def test_bad_record_has_filename_and_line_number(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text("\n{}\n")
    with pytest.raises(ValueError, match=r"broken.jsonl:2:"):
        list(FileAlertSource(path).poll())


def test_blank_lines_are_ignored(tmp_path):
    original = Path("fixtures/alerts/alerts.jsonl").read_text().splitlines()[0]
    path = tmp_path / "one.jsonl"
    path.write_text("\n" + original + "\n\n")
    assert len(list(FileAlertSource(path).poll())) == 1


def test_null_provider_marks_everything_unavailable():
    alert = next(iter(FileAlertSource("fixtures/alerts/alerts.jsonl").poll()))
    context = NullContextProvider().gather(alert)
    assert context.flows == []
    assert context.dns == []
    assert context.auth == []
    assert context.prior_alert_count is None
    assert set(context.unavailable) == {"flows", "dns", "auth", "prior_alerts"}
    assert (context.window_end - context.window_start).days == 7
