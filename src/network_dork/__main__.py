"""CLI and configuration-driven composition root."""

from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
import math
import time
from pathlib import Path
import sys
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, SecretStr
import structlog
import typer

from network_dork.audit import (
    AuditChainError,
    JsonlAuditLog,
    current_identity,
    verify_chain,
)
from network_dork.config import AdapterDefinition, Settings, load_config
from network_dork.grounding import check as grounding_check
from network_dork.models import Alert, FailureRecord, TimeSeries
from network_dork.pipeline import InvestigationPipeline
from network_dork.render import (
    render_evidence,
    render_failure,
    render_forecast,
    render_report,
)
from network_dork.prompts import (
    AgentProfile,
    InvestigationPrompt,
    render_system_prompt,
    system_prompt_digest,
)
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
    inner = build_adapter(
        settings,
        "context",
        settings.runtime.context_adapter,
        {"audit": audit},
        resources,
    )
    if settings.runtime.forecast_adapter is None:
        return inner

    # Enrichment decorates the configured provider; it never replaces it.
    series_provider = build_adapter(
        settings,
        "timeseries",
        settings.runtime.timeseries_adapter,
        {"audit": audit},
        resources,
    )
    forecaster = build_adapter(
        settings,
        "forecasters",
        settings.runtime.forecaster_adapter,
        {"audit": audit},
        resources,
    )
    return build_adapter(
        settings,
        "forecast",
        settings.runtime.forecast_adapter,
        {
            "audit": audit,
            "inner_context": inner,
            "series_provider": series_provider,
            "forecaster": forecaster,
        },
        resources,
    )

def agent_profile(settings: Settings) -> AgentProfile:
    return AgentProfile(
        name=settings.agent.name,
        role=settings.agent.role,
        deployment=settings.agent.deployment,
        additional_guidance=settings.agent.additional_guidance,
    )


def wire_pipeline(
    settings: Settings,
    resources: ExitStack,
    *,
    fake: bool = False,
) -> tuple[InvestigationPipeline, Any]:
    identity = current_identity()
    audit = JsonlAuditLog(settings.storage.audit_path, identity)
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

    # Pin the exact weights this run used. A model name alone does not
    # identify what produced a report.
    model_digest: str | None = None
    installed = getattr(llm, "installed_model", None)
    if callable(installed):
        try:
            model_digest = installed().get("digest")
        except Exception:
            model_digest = None

    profile = agent_profile(settings)
    pipeline = InvestigationPipeline(
        source=source,
        context=context,
        llm=llm,
        sink=sink,
        failures=sink,
        outcomes=sink,
        state=SQLiteState(settings.storage.state_path),
        prompts=InvestigationPrompt(model_version, agent=profile),
        model_version=model_version,
        audit=audit,
        grounding=grounding_check,
        model_digest=model_digest,
        system_prompt_digest=system_prompt_digest(profile),
        record_prompt_bodies=settings.audit.record_prompt_bodies,
        max_attempts=settings.llm.max_attempts,
        lease_seconds=max(
            600, math.ceil(settings.llm.timeout_seconds * 2 + 60)
        ),
    )
    return pipeline, llm

def print_outcomes(results, as_json: bool = False) -> int:
    """Print what each alert produced.

    Readable by default: the point of the system is a person forming a
    judgement quickly. --json is there for anything consuming the output.
    """
    failures = 0
    for result in results:
        if as_json:
            typer.echo(result.model_dump_json(indent=2))
        elif isinstance(result, FailureRecord):
            typer.echo(render_failure(result))
        else:
            typer.echo(render_report(result))
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

@app.command("preflight")
def preflight_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Prove both models actually work, before trusting any output.

    Reachability is not the question -- a service can answer and still be
    useless. Each model is given a task with a known right answer: the
    language model must return a report that satisfies the schema, and the
    forecaster must continue a periodic series it has never seen.
    """
    settings = load_config(config)
    failures = 0

    def result(name: str, ok: bool, detail: str) -> None:
        nonlocal failures
        failures += not ok
        typer.echo(f"  {'PASS' if ok else 'FAIL'}  {name:<28} {detail}")

    typer.echo("\nLanguage model (Ollama)")
    with ExitStack() as resources:
        try:
            llm = build_adapter(
                settings, "llm", settings.runtime.llm_adapter, {}, resources
            )
        except Exception as exc:
            result("client", False, f"{type(exc).__name__}: {exc}")
            llm = None

        if llm is not None:
            try:
                installed = llm.installed_model()
                result(
                    "model installed",
                    True,
                    f"{settings.llm.model} digest {installed['digest'][:16]}",
                )
            except Exception as exc:
                result("model installed", False, f"{type(exc).__name__}: {exc}")
                installed = None

            if installed is not None:
                # The real path: a schema-valid report, not merely a response.
                from network_dork.adapters.context.null import (
                    NullContextProvider,
                )

                probe = Alert(
                    source="preflight",
                    alert_id="preflight-001",
                    timestamp=datetime.now(timezone.utc),
                    title="Preflight check alert",
                    description="Synthetic alert used to verify the model.",
                    src_ip="10.0.0.1",
                    dst_ip=None,
                    host=None,
                    domains=[],
                    original={},
                )
                context = NullContextProvider().gather(probe)
                prompts = InvestigationPrompt(
                    settings.llm.model, agent=agent_profile(settings)
                )
                system, user = prompts.render(context)
                started = time.monotonic()
                try:
                    raw = llm.complete(system, user)
                    elapsed = time.monotonic() - started
                except Exception as exc:
                    result("completes a request", False, f"{type(exc).__name__}: {exc}")
                    raw = None

                if raw is not None:
                    result("completes a request", True, f"{elapsed:.1f}s, {len(raw):,} chars")
                    try:
                        report = InvestigationPipeline._validate_response(
                            raw, probe, context, settings.llm.model, user
                        )
                        result("returns a valid report", True, f"confidence {report.confidence}")
                    except (ValueError, TypeError) as exc:
                        result(
                            "returns a valid report",
                            False,
                            f"{type(exc).__name__}: {str(exc)[:80]}",
                        )
                    else:
                        violations = grounding_check(report, context)
                        result(
                            "report passes grounding",
                            not violations,
                            violations[0][:70] if violations else "no violations",
                        )

    typer.echo("\nForecaster")
    with ExitStack() as resources:
        try:
            forecaster = build_adapter(
                settings,
                "forecasters",
                settings.runtime.forecaster_adapter,
                {},
                resources,
            )
            result("client", True, settings.runtime.forecaster_adapter)
        except Exception as exc:
            result("client", False, f"{type(exc).__name__}: {exc}")
            forecaster = None

        if forecaster is not None:
            # A known-answer test. The series repeats exactly, so a working
            # forecaster continues it; a broken one cannot fake this.
            period = 288
            cycles = 4
            values = [
                round(10 + 40 * math.sin(math.pi * (index % period) / period) ** 2, 3)
                for index in range(period * cycles)
            ]
            horizon = 24
            series = TimeSeries(
                metric="conn_count",
                entity="preflight",
                bucket_seconds=300,
                start=datetime.now(timezone.utc)
                - timedelta(seconds=300 * len(values)),
                values=values,
            )
            expected = [
                round(10 + 40 * math.sin(math.pi * ((len(values) + i) % period) / period) ** 2, 3)
                for i in range(horizon)
            ]
            started = time.monotonic()
            try:
                prediction = forecaster.forecast(series, horizon)
                elapsed = time.monotonic() - started
            except Exception as exc:
                result("produces a forecast", False, f"{type(exc).__name__}: {exc}")
                prediction = None

            if prediction is not None:
                result(
                    "produces a forecast",
                    True,
                    f"{elapsed:.1f}s, model {prediction.model}",
                )
                banded = all(
                    low <= median <= high
                    for low, median, high in zip(
                        prediction.lower, prediction.median, prediction.upper
                    )
                )
                result(
                    "band brackets the median",
                    banded,
                    "ordered" if banded else "quantiles cross",
                )
                amplitude = max(expected) - min(expected)
                error = sum(
                    abs(p - e) for p, e in zip(prediction.median, expected)
                ) / horizon
                relative = error / amplitude if amplitude else 1.0
                result(
                    "continues a known series",
                    relative < 0.25,
                    f"mean error {error:.1f} = {relative:.0%} of amplitude",
                )

    typer.echo("")
    if failures:
        typer.echo(f"{failures} check(s) failed.", err=True)
        raise typer.Exit(code=1)
    typer.echo("Both models are working.")


@app.command("trace")
def trace_command(
    alert_id: Annotated[str, typer.Option("--alert-id")],
    config: Annotated[Path | None, typer.Option("--config")] = None,
    fake: Annotated[
        bool,
        typer.Option("--fake", help="Deterministic test client, no real model."),
    ] = False,
    show_prompt: Annotated[
        bool, typer.Option("--show-prompt", help="Print the full model input.")
    ] = False,
) -> None:
    """Walk one alert through every stage and show the work.

    Nothing is written: no report, no state, no lease. Run it as often as you
    like on the same alert. This is the command for understanding what the
    engine does and for judging whether its answer is any good.
    """
    settings = load_config(config)
    profile = agent_profile(settings)

    with ExitStack() as resources:
        source = source_for(settings, resources)
        matches = [a for a in source.poll() if a.alert_id == alert_id]
        if not matches:
            raise typer.BadParameter(f"Alert not found: {alert_id}")
        alert = matches[0]

        typer.echo("\n=== 1. THE ALERT (this already fired somewhere) ===")
        typer.echo(f"  id       {alert.alert_id}   from {alert.source}")
        typer.echo(f"  time     {alert.timestamp:%Y-%m-%d %H:%M UTC}")
        typer.echo(f"  title    {alert.title}")
        if alert.description:
            typer.echo(f"  detail   {alert.description}")

        audit = JsonlAuditLog(settings.storage.audit_path, current_identity())
        context = context_for(settings, audit, resources).gather(alert)

        typer.echo(
            "\n=== 2. EVIDENCE GATHERED (read-only, from your telemetry) ==="
        )
        typer.echo(render_evidence(context))

        typer.echo(
            "\n=== 3. FORECAST EVIDENCE (the forecaster's contribution) ==="
        )
        typer.echo(render_forecast(context))

        name = "fake" if fake else settings.runtime.llm_adapter
        definition = adapter_definition(settings, "llm", name)
        expected = FAKE_REFERENCE if fake else OLLAMA_REFERENCE
        if definition.class_path != expected:
            raise typer.BadParameter(
                "Runtime inference must use Ollama; fake requires --fake"
            )
        llm = build_adapter(settings, "llm", name, {"audit": audit}, resources)
        model_version = "fake:test-only" if fake else settings.llm.model
        prompts = InvestigationPrompt(model_version, agent=profile)
        system, user = prompts.render(context)

        offered = json.loads(user)["allowed_context_ids"]
        typer.echo("\n=== 4. WHAT THE LANGUAGE MODEL IS ASKED ===")
        typer.echo(f"  agent        {profile.name} ({profile.role})")
        typer.echo(f"  model        {model_version}")
        typer.echo(f"  prompt size  {len(system) + len(user):,} characters")
        typer.echo(f"  may cite     {len(offered)} evidence identifiers:")
        for identifier in offered:
            typer.echo(f"                 {identifier}")
        if show_prompt:
            typer.echo("\n--- system prompt ---")
            typer.echo(system)
            typer.echo("--- evidence given to the model ---")
            typer.echo(json.dumps(json.loads(user), indent=2)[:4000])

        typer.echo("\n=== 5. WHAT THE MODEL ANSWERED ===")
        try:
            raw = llm.complete(system, user)
        except Exception as exc:
            typer.echo(f"  model call failed: {type(exc).__name__}: {exc}")
            raise typer.Exit(code=1) from exc
        typer.echo(f"  {len(raw):,} characters of JSON returned")

        typer.echo("\n=== 6. CHECKS (why an answer can be rejected) ===")
        try:
            report = InvestigationPipeline._validate_response(
                raw, alert, context, model_version, user
            )
            typer.echo("  schema      PASS  shape, identity, cited ids all valid")
        except (ValueError, TypeError) as exc:
            typer.echo(f"  schema      FAIL  {exc}")
            typer.echo("\n  The model's answer was not usable. In a real run it "
                       "would be retried, then stored as a failure record.")
            raise typer.Exit(code=1) from exc

        violations = grounding_check(report, context)
        if violations:
            typer.echo("  grounding   FAIL")
            for violation in violations:
                typer.echo(f"                {violation}")
            typer.echo("\n  The report was well formed but not supportable. In a "
                       "real run it would be retried, then stored as a failure.")
            raise typer.Exit(code=1)
        typer.echo("  grounding   PASS  entities cited, no action claims, "
                   "confidence supportable")

        typer.echo("\n=== 7. WHAT AN ANALYST READS ===")
        typer.echo(render_report(report, context))


@app.command("readiness")
def readiness_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    limit: Annotated[
        int, typer.Option("--limit", help="Hosts to list.")
    ] = 20,
) -> None:
    """Show which hosts have enough history for forecast enrichment.

    Forecasting needs a host observed long enough for its daily and weekly
    rhythm to be visible. Nothing is being trained while you wait: the
    forecasters do not learn, and TimesFM is frozen and zero-shot. The wait
    is for telemetry to accumulate.
    """
    settings = load_config(config)
    forecast = settings.forecast
    with ExitStack() as resources:
        provider = build_adapter(
            settings,
            "timeseries",
            settings.runtime.timeseries_adapter,
            {},
            resources,
        )
        coverage = getattr(provider, "coverage", None)
        if not callable(coverage):
            raise typer.BadParameter(
                f"{settings.runtime.timeseries_adapter} cannot report coverage"
            )
        report = coverage(
            end=datetime.now(timezone.utc),
            buckets=forecast.history_buckets + forecast.horizon_buckets,
            bucket_seconds=forecast.bucket_seconds,
        )

    if forecast.baseline_started_at is not None:
        needed = timedelta(
            seconds=forecast.bucket_seconds * forecast.history_buckets
        )
        ready_at = forecast.baseline_started_at + needed
        remaining = (ready_at - datetime.now(timezone.utc)).total_seconds()
        if remaining > 0:
            typer.echo(
                f"Baseline period in progress: enrichment begins "
                f"{ready_at.date()} ({remaining / 86400:.1f} days remaining)."
            )
        else:
            typer.echo(f"Baseline period complete since {ready_at.date()}.")

    if not report:
        typer.echo("No hosts observed in the configured window.", err=True)
        return

    ready = sorted(
        (item for item in report.values() if item.ready),
        key=lambda item: -item.span_seconds,
    )
    waiting = sorted(
        (item for item in report.values() if not item.ready),
        key=lambda item: -item.span_seconds,
    )
    typer.echo(
        f"\n{len(ready)} of {len(report)} hosts have enough history "
        f"({forecast.history_buckets * forecast.bucket_seconds / 86400:.0f} "
        "day window)"
    )
    for item in ready[:limit]:
        typer.echo(f"  READY    {item.entity:<20} {item.span_days:.1f} days")
    for item in waiting[:limit]:
        typer.echo(f"  WAITING  {item.entity:<20} {item.reason()}")


@app.command("verify-audit")
def verify_audit_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    path: Annotated[
        Path | None,
        typer.Option("--path", help="Audit file; defaults to the configured one."),
    ] = None,
) -> None:
    """Check the audit file against its own hash chain.

    Detects edited, removed, reordered, and inserted records. It cannot
    detect a rewrite by someone who recomputed every later digest: that needs
    an anchor outside the file.
    """
    settings = load_config(config)
    target = path or settings.storage.audit_path
    try:
        count, head = verify_chain(target)
    except AuditChainError as exc:
        typer.echo(f"FAILED  {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"OK  {count} records verified in {target}")
    typer.echo(f"chain head: {head}")


@app.command("agent")
def agent_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    show_prompt: Annotated[
        bool,
        typer.Option("--prompt", help="Print the full resolved system prompt."),
    ] = False,
) -> None:
    """Show what this agent is configured to be.

    Identity and local guidance are configurable; the rules that make this an
    investigator rather than an actor are fixed in code. Both are shown so an
    operator can see exactly what the model is told.
    """
    settings = load_config(config)
    profile = agent_profile(settings)
    typer.echo(f"name:        {profile.name}")
    typer.echo(f"role:        {profile.role}")
    typer.echo(f"deployment:  {profile.deployment or '(unset)'}")
    typer.echo(
        f"guidance:    {profile.additional_guidance or '(none)'}"
    )
    typer.echo(f"prompt sha256: {system_prompt_digest(profile)}")
    typer.echo(
        "\nFixed in code and not settable: investigates rather than detects, "
        "cannot act, treats supplied evidence as untrusted.",
        err=True,
    )
    if show_prompt:
        typer.echo("\n--- resolved system prompt ---")
        typer.echo(render_system_prompt(profile))


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

@app.command("eval")
def eval_command(
    config: Annotated[Path | None, typer.Option("--config")] = None,
    corpus: Annotated[
        Path, typer.Option("--corpus", help="Directory holding corpus.json.")
    ] = Path("fixtures/timeseries"),
    forecaster_name: Annotated[
        str,
        typer.Option(
            "--forecaster",
            help="Configured forecaster to score, or 'all' to compare.",
        ),
    ] = "baseline",
    threshold: Annotated[
        float,
        typer.Option("--threshold", help="Operating point to report in detail."),
    ] = 24.0,
) -> None:
    """Score forecasters against the labelled corpus.

    Reports the confounder flag rate alongside precision and recall: benign
    activity that looks anomalous is what decides whether an analyst keeps
    trusting this evidence.
    """
    from network_dork.evaluation import (
        Corpus,
        attacks_found,
        evaluate,
        noise_floor,
        recall_by_category,
        sweep,
        tally,
    )

    settings = load_config(config)
    loaded = Corpus.load(corpus)
    names = (
        sorted(settings.adapters.get("forecasters", {}))
        if forecaster_name == "all"
        else [forecaster_name]
    )

    thresholds = [4.0, 8.0, 16.0, 24.0, 32.0, 48.0, 64.0, 128.0]
    for name in names:
        # A forecaster that cannot be built or reached is reported and
        # skipped: an unavailable sidecar must not abort a comparison run.
        try:
            with ExitStack() as resources:
                model = build_adapter(
                    settings, "forecasters", name, {}, resources
                )
                points, skipped = evaluate(
                    model,
                    loaded,
                    history_buckets=settings.forecast.history_buckets,
                    horizon_buckets=settings.forecast.horizon_buckets,
                    min_observations=settings.forecast.min_observations,
                    min_span_fraction=settings.forecast.min_span_fraction,
                )
        except Exception as exc:
            typer.echo(
                f"\n=== {name} ===\nunavailable: {type(exc).__name__}: "
                f"{str(exc)[:200]}",
                err=True,
            )
            continue

        if not points:
            typer.echo(f"\n{name}: no evaluable points", err=True)
            continue

        positives = sum(1 for point in points if point.malicious)
        typer.echo(f"\n=== {name} ===")
        typer.echo(
            f"{len(points)} evaluated, {skipped} skipped for insufficient "
            f"history, {positives} malicious"
        )
        typer.echo(
            f"{'thresh':>7} {'prec':>6} {'recall':>7} {'F1':>6} "
            f"{'FP rate':>8} {'confounders flagged':>20}"
        )
        for board in sweep(points, thresholds):
            typer.echo(
                f"{board.threshold:7.2f} {board.precision:6.2f} "
                f"{board.recall:7.2f} {board.f1:6.2f} "
                f"{board.false_positive_rate:8.3f} "
                f"{board.confounder_flags:>10}/{board.confounder_total:<9}"
            )

        typer.echo("\nBenign noise floor per metric (highest benign score):")
        floors = noise_floor(points)
        for metric in sorted(floors):
            configured = settings.forecast.min_score_by_metric.get(
                metric, settings.forecast.min_score
            )
            typer.echo(
                f"  {metric:<24} floor {floors[metric]:7.2f}   "
                f"configured threshold {configured:7.2f}"
                + ("   TOO LOW" if configured <= floors[metric] else "")
            )

        per_metric = settings.forecast.min_score_by_metric
        board = tally(points, per_metric, settings.forecast.min_score)
        typer.echo("\nAt the configured per-metric thresholds:")
        found = attacks_found(points, per_metric, settings.forecast.min_score)
        by_category = recall_by_category(
            points, per_metric, settings.forecast.min_score
        )
        for category in sorted(by_category):
            hits, total = by_category[category]
            verdict = "FOUND" if found.get(category) else "MISSED"
            typer.echo(
                f"  {category:<22} {verdict:<7} "
                f"({hits}/{total} evaluation points)"
            )
        typer.echo(
            f"  {'benign flagged':<22} "
            f"{board.confounder_flags}/{board.confounder_total} "
            f"(false positives: {board.false_positives})"
        )


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
    as_json: Annotated[
        bool, typer.Option("--json", help="Machine-readable output.")
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
    if print_outcomes(results, as_json):
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
            "max_records": "${context.max_records}",
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
        "agent": settings.agent.model_dump(),
        "system_prompt_sha256": system_prompt_digest(agent_profile(settings)),
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
