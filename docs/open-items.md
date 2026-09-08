# Open items

Known gaps, stated plainly. Anything listed here is a real limitation, not a
placeholder. Several would matter for a federal authorization package.

## Security and compliance

### ~~Plaintext HTTP to LAN endpoints~~ — fixed

Plaintext HTTP is now refused to anything but loopback. `security.
allow_plaintext` is an explicit opt-out for a container bridge or lab, and
the demo compose file sets it because `host.docker.internal` is host-local
but not loopback.

### The audit chain is tamper-evident, not tamper-proof

`audit.py` now hash-chains every record, so edits, deletions, reordering and
insertions are detected by `python -m network_dork verify-audit`, which names
the first record that disagrees.

**What it still does not do:** someone with write access can rewrite the file
from a chosen point and recompute every subsequent digest. The chain also
cannot prove records are missing from the *end* — a truncated file is
internally consistent.

**Both need an anchor outside the file:** ship the chain head to a remote log
service, or record it periodically somewhere the application cannot reach.
An append-only mount remains the deployment-side control.

### No SBOM, dependency scanning, or signed releases

CI runs tests only. For a federal delivery you would expect an SBOM per
build, a vulnerability scan, and provenance attestation.

**Fix:** add `pip-audit` and CycloneDX generation to CI. The runtime
dependency set is five pure-Python packages, so this is small — until the
TimesFM sidecar is deployed, which adds torch.

### No linting or type checking in CI

There is no `ruff` or `mypy` step. The code is annotated throughout but
nothing enforces it.

## Scale

### Log scanning is linear per alert, per metric

`ZeekLogsContextProvider` and `ZeekBucketTimeSeriesProvider` both scan the
whole log file for each alert. Measured on synthetic data:

| Alerts | conn.log rows | Per alert |
|---:|---:|---:|
| 10 | 1,000 | 11 ms |
| 50 | 20,000 | 187 ms |
| 100 | 100,000 | 1,183 ms |

Purely linear. A real `conn.log` is millions of rows per day, so this is
roughly a minute per alert of scanning before any inference.

Enrichment made this **worse**, as predicted when it was proposed: four
metrics each trigger their own scan of the same file.

**Fix, in order of effort:** cache the bucketed series per (host, metric,
window) within a run — the four metrics currently rescan identical data.
Then use the OpenSearch provider, which pushes filtering to an index. A
pre-aggregated bucket store is the real answer at volume.

The file-based providers are honest defaults for a fixture corpus and a small
deployment. They are not a production ingest path, and the module docstrings
say so.

### Processing is sequential

`run_once` handles one alert at a time. With a 120-second model timeout and
three attempts, a dead Ollama costs six minutes per alert before the batch
finishes failing. There is no concurrency and no circuit breaker.

## Evaluation

### Thresholds are tuned on the corpus they are scored against

Eight benign windows is not a holdout. Each per-metric threshold sits just
above a benign maximum estimated from very few samples. They are starting
points, not constants.

`python -m network_dork eval` prints each metric's measured floor beside its
configured threshold and marks any that is too low. Re-derive on your own
telemetry before trusting them.

### The corpus is synthetic

Nine hosts, three campaigns, three benign confounders, generated from a seed.
It was written to be realistic, and it has already been wrong once — the
first version did not model beaconing at all. The numbers justify design
decisions; they do not predict field performance.

### `min_observations` and `min_span_fraction` are judgement, not measurement

They decide which hosts get forecast at all (currently: 100 observations
spanning at least half the requested window). Nothing measured those values.
`python -m network_dork readiness` shows their effect on your own telemetry.

### TimesFM has never been run

The adapter, sidecar, weight staging, and licence guards exist and are
tested against a mock transport. No real TimesFM inference has happened in
this repository. `make eval` compares it against the baseline the moment a
sidecar is running.

## Model behaviour

### Grounding does not stop prompt injection

Text injected into an alert becomes supplied evidence, so an IP named there
is grounded by definition. Entity grounding catches *hallucination*. What
caught the injection case in testing was the action-claim and confidence
checks.

Do not present grounding as an injection defence. The structural controls —
no action code, split credentials, pinned endpoints — are what make injection
non-catastrophic.

### The action lexicons are narrow and hand-written

`grounding.py` uses regular expressions to spot claimed and recommended
actions. They are tested in both directions, including cases that must
*not* be rejected ("the connection was blocked by the firewall" describes
telemetry). They will still miss phrasings and should be tuned against real
model output rather than extended speculatively.

### No report quality measurement against ground truth

`fixtures/ground_truth.yaml` carries MITRE and NIST labels for the twelve
alert fixtures, and nothing scores model reports against them. The forecast
evaluation exists; the equivalent for report content does not. It needs a
real model run, so it could not be built in an environment without Ollama.
