# Running both models in a VM

Goal: Qwen and TimesFM both provably working, verified by a command rather
than by them appearing to start.

## Machine

| | Minimum (3B) | Comfortable (7B) |
|---|---|---|
| RAM | 16 GB | 32 GB |
| Disk | 30 GB | 50 GB |
| CPU | 4 cores | 8 cores |
| GPU | none | none |

Both models run on CPU. Qwen 2.5 3B is ~2 GB, TimesFM 2.5 is ~800 MB, and
the torch image is ~2.5 GB. No CUDA anywhere.

The RAM figure is driven by the language model plus its KV cache, and the
cache is not small at the shipped `num_ctx` of 24,576:

| | Weights (q4) | KV cache at 24k ctx | Together |
|---|---:|---:|---:|
| `qwen2.5:3b-instruct` | ~1.9 GB | ~0.9 GB | ~2.8 GB |
| `qwen2.5:7b-instruct` | ~4.7 GB | ~1.4 GB | ~6.1 GB |

Those cache figures are arithmetic from each model's published layer and
KV-head counts, not measurements on your hardware. Check the real number
with `ollama ps` while a run is in flight. Both fit in 16 GB alongside the
TimesFM container; 7B on 8 GB will swap.

Ubuntu 22.04 or 24.04. Docker is only needed for the forecaster.

## 1. Base

```sh
sudo apt update && sudo apt install -y git curl docker.io
sudo usermod -aG docker $USER && newgrp docker
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/jacobjoshy16-commits/network-dork.git
cd network-dork && git checkout arena/01a07424-network-dork
uv sync --extra dev
make test
```

If the tests fail, stop. Nothing below is meaningful.

## 2. Qwen

```sh
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &                          # or: systemctl start ollama
ollama pull qwen2.5:3b-instruct         # ~2 GB
```

Ollama listens on `127.0.0.1:11434`, which is what the endpoint allowlist
expects. Do not bind it to `0.0.0.0` — plaintext HTTP off loopback is
refused, deliberately.

**Verify:**

```sh
python -m network_dork preflight
```

Expect the language-model section to pass four checks: the model is
installed, it completes a request, it returns a schema-valid report, and that
report passes grounding.

The forecaster section will fail until step 3. That is correct.

**If "returns a valid report" fails**, the model is producing malformed JSON.
That is a real result about a 3B model, not a bug. Section 6 makes the
comparison against 7B a measurement rather than an impression.

**Watch the elapsed time** preflight prints for "completes a request". It is
a floor: the probe prompt is nearly empty, while a real investigation sends
up to 60,000 characters. If the probe already takes 30 seconds on 3B, a full
prompt on 7B will exceed the 120-second default and every alert will fail as
`llm_unavailable`. Raise `NETWORK_DORK_TIMEOUT_SECONDS` before blaming the
model.

## 3. TimesFM

Weights are staged once, on a machine with internet, then moved. The sidecar
never downloads anything at request time.

```sh
uv run pip install huggingface_hub
uv run python scripts/stage_timesfm_weights.py \
    --destination ./models/timesfm-2.5-200m
```

That writes a `SHA256SUMS` manifest so the transfer can be verified on an
air-gapped target. Only Apache-2.0 checkpoints are accepted; 3.x is refused
by the script, the sidecar, and the client.

```sh
make timesfm-up            # builds and starts the container
docker compose --profile timesfm logs -f timesfm
```

First start compiles the model and takes a few minutes. Wait for it before
verifying.

```sh
curl -s http://127.0.0.1:11435/health
NETWORK_DORK_FORECASTER_ADAPTER=timesfm python -m network_dork preflight
```

Expect the forecaster section to pass three checks: it produces a forecast,
its band brackets its median, and **it continues a known series**. The last
one is the one that matters — it hands the model four cycles of a periodic
series it has never seen and requires the continuation within 25% of the
amplitude. A model that loaded but returns noise fails this.

For reference, the baseline scores 0% error on that test.

## 4. Both together

```sh
python scripts/make_sample_network.py --destination var/sample
export NETWORK_DORK_ALERTS_PATH=var/sample/alerts.jsonl
export NETWORK_DORK_ZEEK_DIRECTORY=var/sample/zeek
export NETWORK_DORK_FORECAST_ADAPTER=enrichment
export NETWORK_DORK_FORECASTER_ADAPTER=timesfm

python -m network_dork preflight       # both sections pass
python -m network_dork trace --alert-id sample-beacon
```

Drop `--fake` and every stage is real: TimesFM produces the stage 3 evidence,
Qwen reads it and writes the stage 7 report.

## 5. The comparison worth running

```sh
python -m network_dork eval --forecaster all
```

Scores TimesFM and the baseline against the same labelled corpus. The
baseline currently finds all three campaigns with zero benign windows
flagged, so the question is not whether TimesFM works but whether it is
*better*:

- Does it find all three?
- Does it flag any benign window? (the baseline flags none)
- Does it lower the per-metric noise floors, which would let thresholds drop
  and catch weaker attacks?

If it matches the baseline, it is 2.5 GB of dependencies for no gain, and
the honest answer is to leave it off. `docs/evaluation.md` explains the
numbers.

## 6. Which Qwen

A bigger model is a cost, so it should have to earn the RAM. Run the same
fixture corpus under each and score the reports against the labels:

```sh
NETWORK_DORK_MODEL=qwen2.5:3b-instruct python -m network_dork demo
NETWORK_DORK_MODEL=qwen2.5:7b-instruct \
  NETWORK_DORK_TIMEOUT_SECONDS=600 python -m network_dork demo

python -m network_dork eval-reports var/demo/*
```

Each run writes `var/demo/<timestamp>/`, and `eval-reports` reads the
manifest to name the row by model rather than by directory. It reports four
things, in descending order of how much they matter:

| Column | What it means |
|---|---|
| `usable` | Reports that passed schema and grounding. A model that fails a third of alerts is not usable, however good the rest read. |
| `evidence` | Reports citing something beyond the alert itself. Low means it wrote from the title and ignored the evidence gathered for it. |
| `MITRE ok` | Correct technique out of those it was willing to name. Weighted lightly — the prompt tells it to emit null rather than guess, and declining is not scored as wrong. |
| `benign hi` | High confidence on an alert the labels call benign. This is the expensive mistake: it is what teaches an analyst to stop reading. |

**A larger model earns its cost by raising `usable` and `evidence` without
raising `benign hi`.** If 7B only moves `MITRE ok`, it bought you a guess.

Twelve alerts is a small sample and the labels are synthetic, so treat a
one- or two-report difference as noise. A model that fails half the corpus
is not noise.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Ollama transport request failed` | `ollama serve` not running |
| `Configured model is not installed` | `ollama pull` not run, or model name differs |
| `Forecast transport failed` | Sidecar not up, or still compiling |
| `Refusing plaintext HTTP` | Endpoint is not loopback; use https or set `security.allow_plaintext` |
| `predates hash chaining` | Audit file from an older build; move it aside |
| `No metric had enough history` | Host has under ~14 days of telemetry; run `readiness` |
| Sidecar OOM | Lower `NETWORK_DORK_TIMESFM_MAX_CONTEXT` (default 8192) |
| Every alert fails `llm_unavailable` on 7B | Timeout too low; raise `NETWORK_DORK_TIMEOUT_SECONDS` |
| Host swaps hard on 7B | KV cache; lower `NETWORK_DORK_NUM_CTX` *and* `NETWORK_DORK_MAX_INPUT_CHARS` together, or config validation refuses to start |

## What is genuinely unproven

TimesFM has never been executed in this repository — the sidecar was written
against the published API and its model-loading path has only ever run
against a mock. `preflight` exists precisely because that path needs
verifying on first contact rather than assumed. If it fails on your machine,
the fault is most likely in `services/timesfm/app.py`, and the error will
say which call broke.
