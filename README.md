# network-dork

Network-dork is a local AI assistant for security teams who already have alerts but not enough time to investigate them all. It reads alerts from tools you already run, gathers nearby context from local telemetry, and writes a plain-language report for a human analyst. It is designed for environments where cloud security copilots are not acceptable: air-gapped networks, regulated systems, and places where alert data cannot leave the network. It does not create detections and it does not take actions. It only investigates existing alerts with read-only telemetry access and a separate write-only report destination.

## Verification snapshot

- 153 automated tests passing.
- Added phase 6 and 7 coverage for source-format alert adapters, OpenSearch security bootstrapping, packaging, and end-to-end demo flow.
- Verified end-to-end fixture processing with the fake client and with a local HTTP Ollama-compatible test server.
- `python -m network_dork context --alert-id syn-001` returns real fixture context.
- `python -m network_dork run --fake` processes all 12 fixture alerts into reports.

## What it does

Given an existing alert, network-dork can:

1. Read the alert from a normalized file source, Suricata EVE, Zeek notice logs, or OpenSearch.
2. Gather supporting context such as recent flows, DNS activity, authentication events, and prior alert count.
3. Build a constrained prompt for a local Ollama model.
4. Validate the model response against a strict report schema.
5. Persist either a complete investigation report or an explicit failure record.
6. Audit every context query and every persistence attempt.
7. Preserve restart-safe processing state so interrupted runs can recover safely.

## Security boundaries

- **Telemetry is read-only by design:** use a telemetry credential that can search and read, but cannot write.
- **Reports use a separate credential:** only the report sink should be able to create or update analyst outcomes.
- **No response actions exist:** there are no firewall, isolation, blocking, or configuration-change hooks.
- **Runtime stays local:** the Ollama and OpenSearch clients reject public destinations, disable DNS resolution, ignore proxy variables, and refuse redirects.
- **Audit is explicit:** query and write operations record attempt/success/error audit events with timestamps and parameters.

## Quickstart

### Local Python path

Requirements:

- Python 3.11+
- `uv`
- Ollama running locally or on an approved LAN address

Install and test:

```sh
uv sync --extra dev
make test
python -m network_dork adapters
python -m network_dork context --alert-id syn-001
```

Run the deterministic fake pipeline:

```sh
make run-fake
```

Run the real local-model demo:

```sh
ollama pull qwen2.5:3b-instruct
make demo-local
```

### Docker path

Requirements:

- Docker
- Ollama on the host or on an approved LAN endpoint

Build the container environment:

```sh
make up
```

Run the demo inside Docker:

```sh
make demo
```

By default the container talks to `http://host.docker.internal:11434`, which is mapped with Docker's `host-gateway` feature. To use a LAN Ollama server instead:

```sh
NETWORK_DORK_OLLAMA_BASE_URL=http://192.168.1.20:11434 make demo
```

To switch models with one variable:

```sh
NETWORK_DORK_MODEL=qwen2.5:7b-instruct make demo
```

## Architecture

### Investigation path

```text
AlertSource
  -> ContextProvider
  -> PromptRenderer
  -> LLMClient (Ollama only)
  -> schema validation
  -> ReportSink / FailureStore
  -> AuditLog + ProcessedAlertStore
```

### Default local components

- Alert source: normalized file fixtures
- Context provider: Zeek JSON logs
- LLM client: Ollama chat API
- Canonical sink: SQLite
- Audit log: JSONL
- State store: SQLite leases and completion tracking

### Phase-6 source adapters

- `network_dork.adapters.alerts.file:FileAlertSource`
- `network_dork.adapters.alerts.suricata_eve:SuricataEveAlertSource`
- `network_dork.adapters.alerts.zeek_notice:ZeekNoticeAlertSource`
- `network_dork.adapters.alerts.opensearch:OpenSearchAlertSource`

### Optional sinks and context adapters

- `network_dork.adapters.context.opensearch:OpenSearchContextProvider`
- `network_dork.adapters.sinks.jsonl:JsonlReportSink`
- `network_dork.adapters.sinks.opensearch:OpenSearchReportSink`

## Adapting this to your environment

The project is intentionally interface-driven. To adapt it, implement one interface and point configuration at the class.

### `AlertSource`

Contract: `poll() -> Iterable[Alert]`

Implement this when your alerts come from a different SIEM, queue, or export. The adapter should only normalize existing alerts into the shared `Alert` model. It must not create detections.

### `ContextProvider`

Contract: `gather(alert: Alert) -> AlertContext`

Implement this when your telemetry lives somewhere other than the fixture Zeek logs or OpenSearch. The adapter should retrieve nearby evidence for one alert and explicitly mark missing context as unavailable instead of guessing.

### `LLMClient`

Contract: `complete(system: str, user: str) -> str`

Implement this only if you are changing the local inference backend. The current project intentionally supports Ollama only for real inference, plus a deterministic fake client for tests.

### `ReportSink`

Contract: `write(report: InvestigationReport) -> None`

Implement this when your analyst reports must land somewhere other than SQLite, JSONL, or OpenSearch. The sink should be idempotent for the same report and must reject conflicting outcomes.

### `FailureStore`

Contract: `write_failure(failure: FailureRecord) -> None`

The canonical sink also stores explicit failures so malformed model output or outages become auditable artifacts instead of silent drops.

### `OutcomeReader`

Contract: `get_outcome(alert_id: str) -> InvestigationReport | FailureRecord | None`

Used for crash recovery. If a report was already committed before state completion, the pipeline can re-read it and finish safely.

### `AuditLog`

Contract: `record(event: AuditEvent) -> None`

Every context query and every report or failure write goes through the audit log. Production deployments should place this file or service behind stronger append-only controls than ordinary application write access.

### `ProcessedAlertStore`

Contract: claim / renew / finish lease methods

Used to avoid duplicate work and to recover cleanly after interruption. The current implementation uses SQLite leases.

### `PromptRenderer`

Contract: `render(context: AlertContext) -> tuple[str, str]`

Responsible for producing the system prompt and user payload while keeping ground truth and unsupported fields out of model input.

## Configuration

Configuration is layered in this order:

1. `config/default.yaml`
2. optional YAML overlay from `--config` or `NETWORK_DORK_CONFIG`
3. explicit environment variables

Important knobs:

- `NETWORK_DORK_OLLAMA_BASE_URL`
- `NETWORK_DORK_MODEL`
- `NETWORK_DORK_ALERT_ADAPTER`
- `NETWORK_DORK_CONTEXT_ADAPTER`
- `NETWORK_DORK_LLM_ADAPTER`
- `NETWORK_DORK_SINK_ADAPTER`
- `NETWORK_DORK_TELEMETRY_USERNAME` / `NETWORK_DORK_TELEMETRY_PASSWORD`
- `NETWORK_DORK_REPORT_USERNAME` / `NETWORK_DORK_REPORT_PASSWORD`

## OpenSearch security bootstrap

To create distinct read and write identities, use:

```sh
python scripts/bootstrap_opensearch_security.py \
  --base-url http://127.0.0.1:9200 \
  --admin-username admin \
  --admin-password change-me \
  --telemetry-user nd-reader \
  --telemetry-password reader-secret \
  --report-user nd-writer \
  --report-password writer-secret \
  --report-index network-dork-reports \
  --telemetry-index security-alerts-* \
  --telemetry-index network-flows-* \
  --telemetry-index dns-* \
  --telemetry-index auth-*
```

The script also verifies that the telemetry credential cannot write to the report index.

## Repo layout

```text
config/default.yaml
fixtures/
  alerts/
  zeek/
  source_samples/
scripts/bootstrap_opensearch_security.py
src/network_dork/
  __main__.py
  audit.py
  config.py
  interfaces.py
  models.py
  pipeline.py
  prompts.py
  state.py
  adapters/
    alerts/
    context/
    llm/
    sinks/
tests/
```

## Permission-boundary rationale

The application code should not be the only thing preventing writes. In production, the telemetry identity and filesystem mount should be read-only outside the report destination. That way, even a bug or prompt injection attempt cannot turn the investigator into an acting system. Network-dork is useful because it can summarize evidence while remaining structurally unable to change the network it is describing.
