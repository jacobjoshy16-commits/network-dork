"""CLI composition root.

Adapter references are trusted operator configuration, never model input.
"""

from __future__ import annotations

import importlib
import math
from pathlib import Path
from typing import Annotated, Any

import structlog
import typer

from network_dork.audit import JsonlAuditLog
from network_dork.config import Settings, load_config
from network_dork.models import FailureRecord
from network_dork.pipeline import InvestigationPipeline
from network_dork.prompts import InvestigationPrompt
from network_dork.state import SQLiteState

app = typer.Typer(
    name="network-dork",
    no_args_is_help=True,
    help="Local investigation of existing network security alerts.",
)
log = structlog.get_logger()

def load_adapter(reference: str) -> type[Any]:
    module_name, separator, class_name = reference.partition(":")
    if not separator or not module_name or not class_name:
        raise ValueError("Adapter references must use module:class syntax")
    candidate = getattr(importlib.import_module(module_name), class_name)
    if not isinstance(candidate, type):
        raise ValueError(f"Adapter reference is not a class: {reference}")
    return candidate

def configured_class(settings: Settings, kind: str, name: str) -> type[Any]:
    try:
        reference = settings.adapters[kind][name]
    except KeyError as exc:
        raise typer.BadParameter(
            f"No configured {kind} adapter named {name!r}"
        ) from exc
    return load_adapter(reference)

def source_for(settings: Settings):
    return configured_class(settings, "alerts", "file")(
        path=settings.alerts.path
    )

def context_for(settings: Settings, audit: JsonlAuditLog):
    return configured_class(settings, "context", "zeek_logs")(
        directory=settings.context.zeek_directory,
        prior_alerts_path=settings.alerts.path,
        audit=audit,
        window_days=settings.context.window_days,
    )

@app.callback()
def main() -> None:
    """Investigate existing alerts; never detect or act."""

@app.command()
def adapters(
    config: Annotated[
        Path | None, typer.Option("--config", help="Optional YAML overlay.")
    ] = None,
) -> None:
    """List configured adapters and verify their classes import."""
    settings = load_config(config)
    typer.echo("KIND\tNAME\tIMPLEMENTATION")
    for kind, entries in sorted(settings.adapters.items()):
        for name, reference in sorted(entries.items()):
            load_adapter(reference)
            typer.echo(f"{kind}\t{name}\t{reference}")

@app.command("context")
def show_context(
    alert_id: Annotated[str, typer.Option("--alert-id")],
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Print alert-relative supporting context without an LLM call."""
    settings = load_config(config)
    source = source_for(settings)
    matches = [
        alert for alert in source.poll() if alert.alert_id == alert_id
    ]
    if not matches:
        raise typer.BadParameter(f"Alert not found: {alert_id}")
    if len(matches) != 1:
        raise typer.BadParameter(f"Alert ID is not unique: {alert_id}")
    audit = JsonlAuditLog(settings.storage.audit_path)
    context = context_for(settings, audit).gather(matches[0])
    typer.echo(context.model_dump_json(indent=2))

@app.command("run")
def run_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    fake: Annotated[
        bool,
        typer.Option("--fake", help="Explicit test-only deterministic client."),
    ] = False,
) -> None:
    """Process one source poll, preserving state for subsequent runs."""
    settings = load_config(config)
    audit = JsonlAuditLog(settings.storage.audit_path)
    source = source_for(settings)
    context = context_for(settings, audit)
    sink = configured_class(settings, "sinks", "sqlite")(
        path=settings.storage.reports_path,
        audit=audit,
    )

    if fake:
        model_version = "fake:test-only"
        llm = configured_class(settings, "llm", "fake")()
        typer.echo(
            "TEST MODE: deterministic fake responses, not model investigations.",
            err=True,
        )
    else:
        llm_class = configured_class(settings, "llm", "ollama")
        model_version = settings.llm.model
        llm = llm_class(
            base_url=settings.llm.base_url,
            model=settings.llm.model,
            temperature=settings.llm.temperature,
            timeout_seconds=settings.llm.timeout_seconds,
        )

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
    results = pipeline.run_once()
    for result in results:
        typer.echo(result.model_dump_json(indent=2))
    failure_count = sum(
        isinstance(result, FailureRecord) for result in results
    )
    log.info(
        "poll_complete",
        outcomes=len(results),
        failures=failure_count,
        test_mode=fake,
    )
    if failure_count:
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
