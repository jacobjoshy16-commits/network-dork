# How network-dork works

This explains the whole engine: what happens to one alert, why each part
exists, and which decisions were driven by measurement rather than taste.

## The one-sentence version

An alert already fired somewhere. network-dork reads it, gathers nearby
evidence from telemetry you already collect, asks a local language model to
write a plain-language investigation, checks that the answer is supported by
the evidence, and stores it. It cannot create alerts and it cannot act.

## The pipeline, once per alert

```
AlertSource.poll()
        |  existing alerts, normalized
        v
ProcessedAlertStore.claim()          <-- lease; another worker cannot duplicate
        |
        v
ContextProvider.gather()             <-- read-only telemetry
        |  flows, DNS, auth, prior alerts
        |  (+ forecast, if enrichment is on)
        v
PromptRenderer.render()              <-- identity + fixed rules + evidence
        |
        v
LLMClient.complete()                 <-- Ollama, local only
        |  raw JSON
        v
schema validation                    <-- shape, identity, cited ids
grounding.check()                    <-- entities, action claims, confidence
        |
    +---+------------------+
    | passes              | fails, all attempts spent
    v                     v
ReportSink.write()   FailureStore.write_failure()
        |                     |
        +----------+----------+
                   v
        ProcessedAlertStore.finish()
```

Everything above happens under an **audit log**: every telemetry query, every
model call, and every write emits an event carrying who ran it, what was
asked, and what came back.

## The parts

### Alert sources — where work comes from

`poll()` yields normalized `Alert` objects. Adapters exist for a JSON Lines
file, Suricata EVE, Zeek notices, and OpenSearch. An adapter **normalizes**;
it never decides something is worth alerting on. That is the difference
between this and a detection system.

Native identifiers are untrusted. A Zeek `uid` or an OpenSearch `_id`
containing `/../` once redirected a database write to an arbitrary endpoint
(`adapters/identity.py` now rewrites those, keeping distinct inputs distinct
via a digest suffix).

### Context providers — the evidence

`gather(alert)` returns an `AlertContext`: flows, DNS, auth records, a count
of prior alerts, and anything that could not be retrieved, with a reason.

Two properties matter more than they look:

- **Missing evidence is explicit.** `unavailable` names each kind that could
  not be read and why. The model is told what it is not seeing, rather than
  being allowed to infer absence from silence.
- **Evidence is capped.** A busy host once rendered a 3.4 million character
  prompt against a 32,000 character budget. Records are limited per kind,
  nearest the alert kept, and the dropped count reported to the model.

### Forecast enrichment — optional, off by default

A decorator around whichever context provider is configured. It adds a fifth
evidence kind: what this host's traffic normally looks like versus what it
actually did before the alert.

```
telemetry --> TimeSeriesProvider --> Forecaster --> anomaly.score()
              (regular buckets)      (predict +      (observed vs band)
                                      band)
```

Four metrics per host: connection count, bytes out, distinct destinations,
and **connection regularity** — the reciprocal of the coefficient of
variation over a trailing hour. The fourth exists because beaconing is a
rhythm, not a volume: a callback every sixty seconds is a small, dull amount
of traffic that never varies.

Two forecasters implement one interface. `seasonal-naive` (the default,
pure Python) predicts each bucket from the same bucket one period ago, with a
band derived from how badly that rule has done lately. `timesfm` talks to a
sidecar container. **The baseline is the default because it wins**: see
`evaluation.md`.

Enrichment never creates an alert. If the forecaster is down or a host lacks
history, forecast context is marked unavailable and the investigation
continues.

### Prompts — what the agent is

Three parts, and the split is the point:

| Part | Configurable | Why |
|---|---|---|
| Identity (name, role, deployment) | yes | An analyst should know whether a report came from the enclave's investigator or a lab copy |
| Core rules | **no** | A deployment able to edit them could turn the investigator into something else while the audit still said "network-dork" |
| Site guidance | yes | Local conventions — escalation paths, queue names |

`python -m network_dork agent --prompt` prints exactly what the model is
told. The SHA-256 of the resolved prompt goes into every audit record, so a
report is attributable to specific instructions, not just a model name.

### Validation — two independent gates

**Schema validation** proves the shape: every field present, the identity
fields copied exactly, and `context_used` drawn only from identifiers
actually supplied.

**Grounding** (`grounding.py`) checks the prose, which is what an analyst
reads:

- every IP, host, and domain named must appear in the supplied evidence
- no claim that an action was performed
- no recommendation to block, isolate, or reconfigure
- confidence capped when no telemetry was available

A violation is **retryable** — the model gets another attempt — and only
becomes a `FailureRecord` when attempts run out. Failures are stored, not
dropped, so a malformed answer is an auditable artifact.

One honest limit: grounding does **not** defend against prompt injection.
Text injected into an alert *is* supplied evidence, so an IP named there is
grounded by definition. The action-claim and confidence checks are what
caught the injection case; entity grounding catches hallucination.

### Outcomes and state — two stores, different jobs

`ProcessedAlertStore` (SQLite leases) answers "is anyone working on this, and
did it finish?". `ReportSink`/`FailureStore` answer "what was the conclusion?".

Both key on **`(source, alert_id)`**. They did not always: outcomes were once
keyed on `alert_id` alone, so two sensors reusing a native identifier caused
the second alert to be closed with the first alert's report, silently. The
keys now match, and recovery refuses an outcome whose `alert_id` does not
match the alert it was filed under.

Crash safety comes from ordering: the outcome is committed *before* state is
marked complete. A crash between the two is recoverable — the next run finds
the committed outcome, re-writes it idempotently, and finishes the lease.

### Audit — reconstructing a report

Every telemetry query, model call, and write emits an `AuditEvent` with a
`RuntimeIdentity` (run id, user, host, pid — NIST AU-3 wants the subject).
Model calls record prompt and response digests, attempt number, duration,
acceptance, and the rejection reason when one applies.

Prompt and response *bodies* are excluded by default because they carry
telemetry; `audit.record_prompt_bodies` enables full capture where a
deployment wants it.

## Why it cannot act

Four independent layers, in decreasing order of how much I would trust them:

1. **No action code exists.** There is no firewall, isolation, or
   configuration client in the codebase. This is the only one that holds
   against a bug in the others.
2. **Credentials are split.** Telemetry reads; a separate identity writes
   reports. `scripts/bootstrap_opensearch_security.py` creates both and
   verifies the read identity cannot write.
3. **Endpoints are pinned local.** Every HTTP client resolves through an
   allowlist accepting only loopback, RFC 1918, and IPv6 ULA, with no DNS
   and no proxy variables. Octal, decimal, DNS-rebind, and cloud-metadata
   forms are all refused.
4. **The prompt says so.** Weakest layer, listed last deliberately.

## How this got here

The project was audited, and the audit found three defects that were fixed
before anything was added:

| Found | Consequence |
|---|---|
| `alert_id` interpolated into OpenSearch URLs unencoded | A Zeek `uid` could redirect a write to any endpoint |
| Outcome store keyed on `alert_id`, leases on `(source, alert_id)` | An alert silently closed with another alert's report |
| Context errors uncaught | One telemetry failure aborted the batch and stranded a lease |

Then two things the system could not previously do: audit its own inference
(no record existed of what was sent to the model or what came back) and check
its own prose (a report claiming a host was isolated was persisted verbatim).

Then enrichment, and then the evaluation that made the enrichment honest.
The evaluation is what changed the design most:

- The first threshold produced a **64% false-positive rate**. An 80% forecast
  band leaves a fifth of buckets outside it by construction, so "outside the
  band" is an ordinary event, not a finding.
- The corpus **did not model beaconing**. It was a volume bump with ordinary
  variance (CV 0.337 versus 0.292 on a clean host). The finding "beaconing is
  missed" meant something much weaker than it sounded.
- One threshold could not serve four metrics. Their benign noise floors span
  **3.5 to 22.4**, so a bar high enough for `bytes_out` sat at three times the
  beaconing signal's peak.
- Two fixes were tried and **measured to fail** before the one that worked: a
  bounded regularity measure, and tightening the forecast band.

That sequence is the reason to keep the evaluation. Each of those was
plausible when written and wrong when measured.

## Where to look

| Question | File |
|---|---|
| What is the orchestration? | `src/network_dork/pipeline.py` |
| What are the data contracts? | `src/network_dork/models.py` |
| What can a report say? | `src/network_dork/grounding.py` |
| What is the agent told? | `src/network_dork/prompts.py` |
| How is an anomaly scored? | `src/network_dork/anomaly.py` |
| Does the forecaster work? | `docs/evaluation.md` |
| How do I test it myself? | `docs/testing.md` |
| What is still open? | `docs/open-items.md` |
