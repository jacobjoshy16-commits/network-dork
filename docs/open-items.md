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

### Log scanning is linear per alert

`ZeekLogsContextProvider` and `ZeekBucketTimeSeriesProvider` both scan the
whole log file for each alert. Measured on synthetic data:

| Alerts | conn.log rows | Per alert |
|---:|---:|---:|
| 10 | 1,000 | 11 ms |
| 50 | 20,000 | 187 ms |
| 100 | 100,000 | 1,183 ms |

Purely linear. A real `conn.log` is millions of rows per day, so this is
roughly a minute per alert of scanning before any inference.

**Enrichment used to multiply this by four**, as predicted when it was
proposed: each of the four metrics scanned and re-parsed the same file. It
now accumulates every metric in one pass and caches the result against the
file's size and mtime. Measured on a 45,230-row log, four metrics for one
host: **584 ms before, 186 ms after** — a little over 3x, and the trace
output is byte-identical.

That removes the multiplier, not the scan. The remaining cost is one full
pass per alert.

**Fix, in order of effort:** use the OpenSearch provider, which pushes
filtering to an index. A pre-aggregated bucket store is the real answer at
volume. Reading `conn.log` newest-first and stopping once the window is
covered would help a live log, where the rows of interest are at the end.

The file-based providers are honest defaults for a fixture corpus and a
small deployment. They are not a production ingest path, and the module
docstrings say so.

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

### TimesFM 3.0 is licence-blocked for this product

TimesFM 3.0 (330M, native multivariate) would plausibly forecast these
metrics better than 2.5. Its weights ship under
`timesfm-non-commercial-license-v1.0`, which explicitly prohibits production
deployment and third-party mirroring. Only 2.5 and earlier are Apache-2.0.

For an HPE federal product that is a hard blocker, not a caveat, so the
staging script, the sidecar, and the client all refuse a 3.x checkpoint by
name rather than leaving it to a deployment to discover.

**It is permitted for evaluation.** If 2.5 turns out not to beat the
seasonal-naive baseline, comparing 3.0 internally is a legitimate way to
learn whether a learned forecaster helps at all here — the result just
cannot ship without a commercial licence or a hosted route.

### ~~TimesFM has never been run~~ — run, on real weights

TimesFM 2.5-200M has now been executed on staged Apache-2.0 weights via the
sidecar, on an M-series MacBook Air, CPU only. `preflight` passed all three
forecaster checks: it produced a forecast in 4.3 s, its band bracketed its
median, and it continued an unseen periodic series to a mean error of 2% of
amplitude against a 25% tolerance.

Getting there fixed one real defect: the sidecar pinned
`timesfm[torch]==2.5.0`, a version that has never existed on PyPI. The
package version is not the model version — releases run 2.0.2 then 3.0.0,
and 2.0.2 is what ships `TimesFM_2p5_200M_torch`.

**Still unmeasured:** whether it beats the seasonal-naive baseline, which
scores 0% on that same continuation probe. `make eval` answers that and has
not been run against a live sidecar yet.

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

### Report quality is measurable but has never been measured

`python -m network_dork eval-reports` scores a run's reports against
`fixtures/ground_truth.yaml`: usable-output rate, evidence use, MITRE and
NIST precision, and high confidence on benign alerts. The scoring is tested
against scripted outcomes, so the arithmetic is verified.

**No real model has been scored by it.** Every number it can print is
currently hypothetical, because this repository has no Ollama.

One report-level defect has surfaced from a real model, though.
`qwen2.5:3b-instruct` reproduced a `required_identity` timestamp as
`...04.405000+00:00` where the prompt said `...04.406485+00:00` — every
field an analyst cares about correct, the microseconds wrong. The pipeline
rejected the whole report for it. Asking a 3B model to transcribe 32 digits
the application already knows was spending model reliability on nothing, and
would have depressed the `usable` column for a reason unrelated to
investigative quality. The report timestamp is now stamped from this
process's clock; `alert_id` and `model_version` stay strictly checked. The 3B vs 7B
question in `docs/vm-setup.md` §6 is written as a procedure, not a result.

Twelve alerts is also a very small sample. It can tell you a model fails
half the corpus; it cannot resolve a one-report difference.
