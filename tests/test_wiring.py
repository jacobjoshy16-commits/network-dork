from contextlib import ExitStack
from pathlib import Path

import pytest

from network_dork.__main__ import (
    build_adapter,
    resolve_options,
    wire_pipeline,
)
from network_dork.config import (
    AdapterDefinition,
    load_config,
)
from network_dork.models import InvestigationReport

def settings_in(tmp_path):
    settings = load_config(environ={})
    settings.storage.state_path = tmp_path / "state.sqlite3"
    settings.storage.reports_path = tmp_path / "reports.sqlite3"
    settings.storage.audit_path = tmp_path / "audit.jsonl"
    return settings

def test_option_references_preserve_types_and_inject_services():
    settings = load_config(environ={})
    audit = object()
    resolved = resolve_options(
        {
            "path": "${alerts.path}",
            "days": "${context.window_days}",
            "audit": "${services.audit}",
            "literal": "not a reference",
        },
        settings,
        {"audit": audit},
    )
    assert isinstance(resolved["path"], Path)
    assert resolved["days"] == 7
    assert resolved["audit"] is audit
    assert resolved["literal"] == "not a reference"

@pytest.mark.parametrize(
    "reference",
    [
        "${services.missing}",
        "${llm.no_such_field}",
        "${llm.__class__}",
        "${}",
    ],
)
def test_invalid_option_references_fail(reference):
    with pytest.raises(ValueError):
        resolve_options(reference, load_config(environ={}), {})

def test_new_adapter_needs_no_registry_edit(tmp_path, monkeypatch):
    module = tmp_path / "organization_source.py"
    module.write_text(
        "class OrganizationSource:\n"
        "    def __init__(self, label):\n"
        "        self.label = label\n"
        "    def poll(self):\n"
        "        return []\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    settings = settings_in(tmp_path)
    settings.adapters["alerts"]["organization"] = AdapterDefinition(
        class_path="organization_source:OrganizationSource",
        options={"label": "operator-supplied"},
    )
    with ExitStack() as resources:
        source = build_adapter(
            settings, "alerts", "organization", {}, resources
        )
        assert source.label == "operator-supplied"
        assert list(source.poll()) == []

def test_wiring_closes_adapter_resources(tmp_path, monkeypatch):
    module = tmp_path / "closable_adapter.py"
    module.write_text(
        "class ClosableAdapter:\n"
        "    closed = False\n"
        "    def close(self):\n"
        "        self.closed = True\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    settings = settings_in(tmp_path)
    settings.adapters["alerts"]["closable"] = AdapterDefinition(
        class_path="closable_adapter:ClosableAdapter"
    )
    with ExitStack() as resources:
        adapter = build_adapter(
            settings, "alerts", "closable", {}, resources
        )
        assert adapter.closed is False
    assert adapter.closed is True

def test_fake_requires_explicit_flag(tmp_path):
    settings = settings_in(tmp_path)
    settings.runtime.llm_adapter = "fake"
    with ExitStack() as resources:
        with pytest.raises(ValueError, match="fake requires --fake"):
            wire_pipeline(settings, resources)

def test_generic_wiring_runs_fixture_corpus_with_explicit_fake(tmp_path):
    settings = settings_in(tmp_path)
    with ExitStack() as resources:
        pipeline, llm = wire_pipeline(settings, resources, fake=True)
        outcomes = pipeline.run_once()
        assert len(llm.calls) == 12
    assert len(outcomes) == 12
    assert all(isinstance(row, InvestigationReport) for row in outcomes)
    assert all(row.model_version == "fake:test-only" for row in outcomes)
