"""CLI and configuration-driven composition root."""

from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
from pathlib import Path
import sys
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, SecretStr
import structlog
import typer

from network_dork.audit import JsonlAuditLog
from network_dork.config import AdapterDefinition, Settings, load_config
from network_dork.models import FailureRecord
from network_dork.pipeline import InvestigationPipeline
from network_dork.prompts import InvestigationPrompt, SYSTEM_PROMPT
from network_dork.state import SQLiteState

app = typer.Typer(
    name="network-dork",
    no_args_is_help=True,
    help="Local investigation of existing network security alerts.",
)

OLLAMA_REFERENCE = "network_dork.adapters.llm.ollama:OllamaClient"
FAKE_REFERENCE = "network_dork.adapters.llm.fake:FakeLLMClient"

def load_adapter(reference: str) -> type[Any]:
    module_name, separator, class_name = reference.partition(":")
    if not separator or not module_name or not class_name:
        raise ValueError("Adapter references must use module:class syntax")
    candidate = getattr(importlib.import_module(module_name), class_name)
    if not isinstance(candidate, type):
        raise ValueError(f"Adapter reference is not a class: {reference}")
    return candidate

def adapter_definition(
    settings: Settings, kind: str, name: str
) -> AdapterDefinition:
    try:
        definition = settings.adapters[kind][name]
    except KeyError as exc:
        raise typer.BadParameter(
            f"No configured {kind} adapter named {name!r}"
        ) from exc
    if isinstance(definition, str):
        return AdapterDefinition(class_path=definition)
    return definition

def resolve_options(
    value: Any,
    settings: Settings,
    services: dict[str, Any],
) -> Any:
    """Resolve complete ${...} references without eval or string expansion.

    References preserve types: Paths remain Paths, numbers remain
    numbers, and injected services remain service instances.
    """
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        reference = value[2:-1]
        parts = reference.split(".")
        if not parts or any(not part or part.startswith("_") for part in parts):
            raise ValueError("Invalid adapter option reference")
        if parts[0] == "services":
            current: Any = services
            parts = parts[1:]
        else:
            current = settings
        for part in parts:
            if isinstance(current, BaseModel):
                if part not in type(current).model_fields:
                    raise ValueError("Unknown adapter setting reference")
                current = getattr(current, part)
            elif isinstance(current, dict) and part in current:
                current = current[part]
            else:
                raise ValueError("Unknown adapter service or setting reference")
        if isinstance(current, SecretStr):
            return current.get_secret_value()
        return current
    if isinstance(value, dict):
        return {
            key: resolve_options(item, settings, services)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            resolve_options(item, settings, services)
            for item in value
        ]
    return value

def build_adapter(
    settings: Settings,
    kind: str,
    name: str,
    services: dict[str, Any],
    resources: ExitStack,
) -> Any:
    definition = adapter_definition(settings, kind, name)
    constructor = load_adapter(definition.class_path)
    options = resolve_options(definition.options, settings, services)
    instance = constructor(**options)
    close = getattr(instance, "close", None)
    if callable(close):
        resources.callback(close)
    return instance

def source_for(settings: Settings, resources: ExitStack):
    return build_adapter(
        settings,
        "alerts",
        settings.runtime.alert_adapter,
        {},
        resources,
    )

def context_for(
    settings: Settings,
    audit: JsonlAuditLog,
    resources: ExitStack,
):
    return build_adapter(
        settings,
        "context",
        settings.runtime.context_adapter,
        {"audit": audit},
        resources,
    )

def wire_pipeline(
    settings: Settings,
    resources: ExitStack,
    *,
    fake: bool = False,
) -> tuple[InvestigationPipeline, Any]:
    audit = JsonlAuditLog(settings.storage.audit_path)
    services = {"audit": audit}
    source = source_for(settings, resources)
    context = context_for(settings, audit, resources)
    sink = build_adapter(
        settings,
        "sinks",
        settings.runtime.sink_adapter,
        services,
        resources,
    )

    # The canonical default sink owns recovery and explicit failures.
    # Optional external sinks will be wired behind a canonical outcome
    # store when those adapters are delivered.
    for method in ("write", "write_failure", "get_outcome"):
        if not callable(getattr(sink, method, None)):
            raise ValueError(
                "Selected canonical sink lacks required outcome storage"
            )

    name = "fake" if fake else settings.runtime.llm_adapter
    definition = adapter_definition(settings, "llm", name)
    expected = FAKE_REFERENCE if fake else OLLAMA_REFERENCE
    if definition.class_path != expected:
        raise ValueError(
            "Runtime inference must use Ollama; fake requires --fake"
        )
    llm = build_adapter(settings, "llm", name, services, resources)
    model_version = "fake:test-only" if fake else settings.llm.model

    pipeline = InvestigationPipeline(
        source=source,
        context=context,
        llm=llm,
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=SQLiteState(settings.storage.state_path),
        prompts=InvestigationPrompt(model_version),
        model_version=model_version,
        max_attempts=settings.llm.max_attempts,
        lease_seconds=max(
            600, math.ceil(settings.llm.timeout_seconds * 2 + 60)
        ),
    )
    return pipeline, llm

def print_outcomes(results) -> int:
    failures = 0
    for result in results:
        typer.echo(result.model_dump_json(indent=2))
        failures += isinstance(result, FailureRecord)
    typer.echo(
        f"Completed: {len(results)}; failures: {failures}",
        err=True,
    )
    return failures

@app.callback()
def main() -> None:
    """Investigate existing alerts; never detect or act."""
    structlog.configure(
        processors=[structlog.processors.JSONRenderer()],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )

@app.command()
def adapters(
    config: Annotated[
        Path | None, typer.Option("--config", help="Optional YAML overlay.")
    ] = None,
) -> None:
    """List configured adapters without constructing or contacting them."""
    settings = load_config(config)
    typer.echo("KIND\tNAME\tIMPLEMENTATION")
    for kind, entries in sorted(settings.adapters.items()):
        for name in sorted(entries):
            definition = adapter_definition(settings, kind, name)
            load_adapter(definition.class_path)
            typer.echo(
                f"{kind}\t{name}\t{definition.class_path}"
            )

@app.command("context")
def show_context(
    alert_id: Annotated[str, typer.Option("--alert-id")],
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Print supporting context without calling an LLM."""
    settings = load_config(config)
    with ExitStack() as resources:
        source = source_for(settings, resources)
        matches = [
            alert for alert in source.poll()
            if alert.alert_id == alert_id
        ]
        if not matches:
            raise typer.BadParameter(f"Alert not found: {alert_id}")
        if len(matches) != 1:
            raise typer.BadParameter(f"Alert ID is not unique: {alert_id}")
        audit = JsonlAuditLog(settings.storage.audit_path)
        context = context_for(
            settings, audit, resources
        ).gather(matches[0])
        typer.echo(context.model_dump_json(indent=2))

@app.command("run")
def run_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    fake: Annotated[
        bool,
        typer.Option(
            "--fake",
            help="Explicit deterministic test client; never real inference.",
        ),
    ] = False,
) -> None:
    """Process one poll and retain restart-safe state."""
    settings = load_config(config)
    if fake:
        typer.echo(
            "TEST MODE: fake responses, not model investigations.",
            err=True,
        )
    with ExitStack() as resources:
        pipeline, _ = wire_pipeline(settings, resources, fake=fake)
        results = pipeline.run_once()
    if print_outcomes(results):
        raise typer.Exit(code=1)

@app.command("demo")
def demo_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir",
            help="New directory for this demo; existing paths are refused.",
        ),
    ] = None,
) -> None:
    """Run the synthetic fixture corpus against real local Ollama."""
    settings = load_config(config)

    # Demo is deliberately the fixture path, independent of an operator's
    # production source selection. It does not read ground-truth labels.
    settings.alerts.path = Path("fixtures/alerts/alerts.jsonl")
    settings.context.zeek_directory = Path("fixtures/zeek")
    settings.runtime.alert_adapter = "file"
    settings.runtime.context_adapter = "zeek_logs"
    settings.runtime.sink_adapter = "sqlite"
    settings.adapters.setdefault("alerts", {})["file"] = AdapterDefinition(
        class_path="network_dork.adapters.alerts.file:FileAlertSource",
        options={"path": "${alerts.path}"},
    )
    settings.adapters.setdefault("context", {})["zeek_logs"] = AdapterDefinition(
        class_path=(
            "network_dork.adapters.context.zeek_logs:"
            "ZeekLogsContextProvider"
        ),
        options={
            "directory": "${context.zeek_directory}",
            "prior_alerts_path": "${alerts.path}",
            "window_days": "${context.window_days}",
            "audit": "${services.audit}",
        },
    )
    settings.adapters.setdefault("sinks", {})["sqlite"] = AdapterDefinition(
        class_path="network_dork.adapters.sinks.sqlite:SQLiteReportSink",
        options={
            "path": "${storage.reports_path}",
            "audit": "${services.audit}",
        },
    )

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )
    destination = output_dir or Path("var/demo") / run_id
    if destination.exists():
        raise typer.BadParameter(
            "Demo output directory already exists; refusing to overwrite it"
        )
    destination.mkdir(parents=True, exist_ok=False)
    settings.storage.state_path = destination / "state.sqlite3"
    settings.storage.reports_path = destination / "reports.sqlite3"
    settings.storage.audit_path = destination / "audit.jsonl"

    fixture_paths = [
        settings.alerts.path,
        settings.context.zeek_directory / "conn.log",
        settings.context.zeek_directory / "dns.log",
        settings.context.zeek_directory / "auth.log",
    ]
    manifest = {
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "started",
        "synthetic_corpus": True,
        "fake_model": False,
        "llm": settings.llm.model_dump(),
        "system_prompt_sha256": hashlib.sha256(
            SYSTEM_PROMPT.encode()
        ).hexdigest(),
        "fixtures_sha256": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in fixture_paths
        },
    }
    manifest_path = destination / "manifest.json"

    def save_manifest() -> None:
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    save_manifest()
    typer.echo(f"Demo artifacts: {destination}", err=True)

    try:
        with ExitStack() as resources:
            pipeline, llm = wire_pipeline(settings, resources)
            # Read-only preflight. Never downloads a missing model.
            manifest["installed_model"] = llm.installed_model()
            save_manifest()
            results = pipeline.run_once()
        failures = print_outcomes(results)
        manifest.update(
            status="completed" if not failures else "completed_with_failures",
            finished_at=datetime.now(timezone.utc).isoformat(),
            outcomes=len(results),
            failures=failures,
        )
        save_manifest()
    except Exception as exc:
        manifest.update(
            status="aborted",
            finished_at=datetime.now(timezone.utc).isoformat(),
            error_type=type(exc).__name__,
        )
        save_manifest()
        typer.echo(
            f"Demo aborted: {type(exc).__name__}. "
            f"See {manifest_path}. No fake fallback was used.",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    if failures:
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
