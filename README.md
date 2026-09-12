# network-dork

Network-dork is a local AI assistant for security teams who already have alerts but not enough time to investigate them all. It reads alerts from tools you already run, gathers nearby context from local telemetry, and writes a plain-language report for a human analyst. It is designed for environments where cloud security copilots are not acceptable: air-gapped networks, regulated systems, and places where alert data cannot leave the network. It does not create detections and it does not take actions. It only investigates existing alerts with read-only telemetry access and a separate write-only report destination.

## What it does

Given an existing alert, network-dork can:

1. Read the alert from a normalized file source, Suricata EVE, Zeek notice logs, or OpenSearch.
2. Gather supporting context such as recent flows, DNS activity, authentication events, and prior alert count.
3. Optionally add forecast evidence: what this host's traffic normally looks
   like against what it actually did before the alert fired.
4. Build a constrained prompt for a local Ollama model.
5. Validate the model response against a strict report schema.
6. Check the report's prose against the supplied evidence, rejecting
   fabricated entities, claimed actions, unsupportable confidence, a benign
   verdict nothing gathered can support, and discussion of an evidence class
   that was never supplied.
7. Persist either a complete investigation report or an explicit failure record.
8. Audit every context query, every model call, and every persistence attempt.
9. Preserve restart-safe processing state so interrupted runs can recover safely.

## What the agent is

Identity is configurable; the constraints are not.

```sh
python -m network_dork agent --prompt      # exactly what the model is told
```

| Setting | Configurable | Purpose |
|---|---|---|
| `agent.name`, `agent.role` | yes | Distinguish an enclave instance from a lab copy |
| `agent.deployment` | yes | Free text describing where this instance runs |
| `agent.additional_guidance` | yes | Local conventions, capped at 4000 characters |
| Investigates rather than detects; cannot act; evidence is untrusted | **no** | Fixed in `prompts.py` |

The SHA-256 of the resolved prompt is recorded in every audit event, so a
report is attributable to specific instructions and not merely to a model
name.

## Security boundaries

- **Telemetry is read-only by design:** use a telemetry credential that can search and read, but cannot write.
- **Reports use a separate credential:** only the report sink should be able to create or update analyst outcomes.
- **No response actions exist:** there are no firewall, isolation, blocking, or configuration-change hooks.
- **Runtime stays local:** the Ollama and OpenSearch clients reject public destinations, disable DNS resolution, ignore proxy variables, and refuse redirects.
- **Audit is explicit:** every telemetry query, model call, and write records
  attempt/success/error events with timestamps, parameters, prompt and
  response digests, and the identity of the process that produced them.
- **Reports are checked, not trusted:** prose naming entities absent from the
  evidence, claiming an action was taken, expressing confidence the context
  cannot support, or calling an alert benign with no telemetry to explain it
  is rejected and retried. A report carries two separate judgements --
  `disposition` (what the evidence supports) and `confidence` (how sure of
  it) -- because one field could not distinguish "the evidence is thin" from
  "there is nothing here".
- **Enrichment never detects:** forecast evidence annotates an existing
  alert. It creates no alerts, so alert volume is unchanged.

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

Score what the model wrote against the labelled fixtures:

```sh
make eval-reports
```

Reports usable-output rate, evidence use, MITRE and NIST precision, and
high confidence on benign alerts. Run `demo` under two models and it names
each row by model, so choosing between `qwen2.5:3b-instruct` and
`qwen2.5:7b-instruct` is a measurement rather than a preference. See
`docs/vm-setup.md` §6.

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
  -> ProcessedAlertStore.claim   (lease; no duplicate work)
  -> ContextProvider             (+ forecast enrichment, optional)
  -> PromptRenderer              (identity + fixed rules + evidence)
  -> LLMClient (Ollama only)
  -> schema validation
  -> grounding checks            (entities, action claims, confidence)
  -> ReportSink / FailureStore
  -> AuditLog + ProcessedAlertStore.finish
```

See `docs/architecture.md` for what each stage does and why.

### Forecast enrichment (optional, off by default)

```sh
NETWORK_DORK_FORECAST_ADAPTER=enrichment python -m network_dork run
```

Bucketizes telemetry into regular series, forecasts the pre-alert window from
the host's own history, and reports where observation left the predicted
range. Four metrics: connection count, bytes out, distinct destinations, and
connection regularity.

Two forecasters implement one interface: `baseline` (seasonal-naive, pure
Python, the default) and `timesfm` (a sidecar container). The baseline is the
default because it wins on the evaluation corpus; `make eval` compares them.

TimesFM weights up to 2.5 are Apache-2.0. The 3.x weights are licensed for
non-commercial use and are refused by the staging script, the sidecar, and
the client.

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

### Seeing what is actually in effect

Settings come from `config/default.yaml`, an optional override file, and
around seventy environment variables layered on top, so no single file
answers "why is it doing that":

```sh
python -m network_dork config --changed     # only what you have overridden
python -m network_dork config --section llm # one section, with defaults
python -m network_dork config-env           # the variable for every setting
```

`config` names the layer each value came from and validates the whole
configuration as a side effect — if it prints, the settings load. Passwords
are shown as `<set>`, never printed, so the output is safe to paste into a
ticket.

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

## Documentation

| Document | Contents |
|---|---|
| **`docs/your-testing-loop.md`** | **Start here: four commands to run and judge it yourself** |
| `docs/vm-setup.md` | Running Qwen and TimesFM together, and proving both work |
| `docs/architecture.md` | How the engine works, end to end |
| `docs/evaluation.md` | Whether the forecaster works, measured |
| `docs/testing.md` | Step-by-step local verification |
| `docs/open-items.md` | Known gaps, stated plainly |

## Repo layout

```text
config/default.yaml
docs/
fixtures/
  alerts/            twelve alert fixtures
  ground_truth.yaml  labels; never enters a prompt
  timeseries/        deterministic forecast corpus
  zeek/              flow, dns and auth evidence
  source_samples/
scripts/
  generate_timeseries_corpus.py
  make_sample_network.py
  stage_timesfm_weights.py
  bootstrap_opensearch_security.py
services/timesfm/     forecasting sidecar, kept out of the runtime
src/network_dork/
  __main__.py         CLI and composition root
  interfaces.py       the ports; pipeline.py imports nothing else
  pipeline.py         orchestration
  models.py           data contracts
  config.py           settings and the endpoint allowlist
  prompts.py          system prompt and agent profile
  grounding.py        rejects ungrounded reports
  audit.py            hash-chained audit log
  state.py            leases and restart safety
  anomaly.py          deviation scoring and the baseline forecaster
  regularity.py       beaconing metric
  evaluation.py       scores forecasters against the corpus
  report_eval.py      scores model reports against the labels
  render.py           human-readable output
  adapters/
    alerts/ context/ forecast/ llm/ sinks/ timeseries/
tests/
```

## Permission-boundary rationale

The application code should not be the only thing preventing writes. In production, the telemetry identity and filesystem mount should be read-only outside the report destination. That way, even a bug or prompt injection attempt cannot turn the investigator into an acting system. Network-dork is useful because it can summarize evidence while remaining structurally unable to change the network it is describing.
