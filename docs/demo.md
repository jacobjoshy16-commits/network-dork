# Running the demo

Twelve minutes, four commands, three alerts. Read this before presenting.

## Be straight about one thing

`--fake` uses a deterministic stub, not a language model. **Stages 1-6 of the
trace are the real system; stage 7 is placeholder text.** Presenting that as
model output would be misleading and someone technical will spot it.

Two honest options:

- **With Ollama** (recommended): `ollama serve`, `ollama pull
  qwen2.5:3b-instruct`, then drop `--fake`. Everything is real.
- **Without Ollama**: run `--fake` and say plainly that stage 7 is a stub, and
  that what you are demonstrating is the evidence pipeline and the controls.
  That is still a real demonstration — it is most of the system.

## Setup, before anyone is watching

```sh
uv sync --extra dev
make test                                     # expect 290 passed
python scripts/make_sample_network.py --destination var/sample

export NETWORK_DORK_ALERTS_PATH=var/sample/alerts.jsonl
export NETWORK_DORK_ZEEK_DIRECTORY=var/sample/zeek
export NETWORK_DORK_FORECAST_ADAPTER=enrichment
export NETWORK_DORK_AUDIT_PATH=var/sample/audit.jsonl
```

That writes 20 days of Zeek-shaped logs for four hosts: one beaconing, one
exfiltrating, two ordinary.

## The demo

### 1. What the agent is (30 seconds)

```sh
python -m network_dork agent
```

Identity is configurable. The rules — investigates rather than detects,
cannot act, evidence is untrusted — are fixed in code. The prompt digest is
recorded on every model call, so a report is attributable to specific
instructions.

### 2. The ordinary host first (2 minutes)

```sh
python -m network_dork trace --alert-id sample-quiet --fake
```

**Show this one first.** Stage 3 reads *"stayed within its predicted
range"*. A SOC audience has been burned by tools that flag everything; lead
with the tool staying quiet.

### 3. The beacon (4 minutes)

```sh
python -m network_dork trace --alert-id sample-beacon --fake
```

Stage 3 now carries 11 findings across three metrics, including
`conn_regularity` — the host's traffic became *too regular*. Beaconing is a
rhythm, not a volume spike, and this is the metric that catches it.

Stage 4 shows those findings offered to the language model as citable
evidence. **That is the whole relationship between the two models:** the
forecaster produces evidence, the language model reads it. They never talk
to each other.

### 4. The exfiltration (2 minutes)

```sh
python -m network_dork trace --alert-id sample-exfil --fake
```

Findings dominated by `bytes_out`. Different attack, different metric, same
pipeline.

### 5. The controls (3 minutes)

```sh
python -m network_dork eval          # measured accuracy on labelled data
python -m network_dork verify-audit  # the audit chain
```

`eval` reports all three campaigns found with **zero** benign windows
flagged. Say that the corpus is synthetic and the thresholds are tuned on it
— a federal audience will respect the caveat far more than the number.

Then tamper with a record and re-run `verify-audit` to show the chain
naming the exact line.

## Questions you should expect, and honest answers

**"Does it learn our network?"**
No. Both forecasters are frozen — the baseline is arithmetic, TimesFM is
zero-shot. What it needs is 14 days of *telemetry* to compare against, not
training. `readiness` shows which hosts qualify. For accreditation this is an
advantage: no training pipeline, no drift, reproducible output.

**"What stops it doing something?"**
Four layers, weakest last: there is no action code in the repository at all;
telemetry credentials are read-only and separate from the report writer;
every endpoint is pinned to loopback or RFC 1918 with TLS required
off-loopback; and the prompt says so.

**"What if someone puts instructions in an alert?"**
It reaches the model — that is unavoidable, the alert is the input. What
stops it mattering is that the system has nothing to act with, and that
reports claiming an action was taken are rejected before storage. Do not
claim grounding blocks injection; it does not.

**"How does it scale?"**
Badly, today, on file-based logs: roughly 1.2 s per alert per metric at
100k log rows, scanning linearly. The OpenSearch adapter pushes filtering
to an index and is the production path. `docs/open-items.md` has the
measurements.

**"Is TimesFM in this?"**
The adapter, sidecar, and licence guards are built and tested, but it has
never actually run. The baseline finds all three campaigns without it. Say
that rather than implying it is in the loop.

## Do not claim

- That it detects threats. It investigates alerts that already fired.
- That the accuracy numbers predict field performance. Synthetic corpus.
- That TimesFM is contributing. It has not been run.
- That the audit log is tamper-proof. It is tamper-*evident*.

The strongest thing about this project for a federal audience is that it
knows and states its own limits. Lead with that.
