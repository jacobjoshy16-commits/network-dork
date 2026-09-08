# Testing network-dork on your own machine

Each step is independent and states what you should see. If a step's output
differs, stop there — later steps build on it.

Nothing here contacts the internet or writes outside the repo, except step 7,
which needs a local Ollama, and step 8, which needs Docker.

---

## 0. Prerequisites

```sh
git clone https://github.com/jacobjoshy16-commits/network-dork.git
cd network-dork
git checkout arena/01a07424-network-dork
```

You need **Python 3.11+** and **uv** (`curl -LsSf https://astral.sh/uv/install.sh | sh`).
Ollama and Docker are only needed for steps 7 and 8.

```sh
uv sync --extra dev
```

---

## 1. Run the test suite

```sh
make test
```

**Expect:** `285 passed`. Takes a few seconds.

This is the fastest signal that the checkout is sound. If anything fails
here, nothing below is meaningful.

---

## 2. Confirm every adapter is importable

```sh
uv run python -m network_dork adapters
```

**Expect:** a table of 16 adapters across 7 kinds (alerts, context, forecast,
forecasters, llm, sinks, timeseries). This constructs nothing and contacts
nothing — it only proves each configured class can be imported.

---

## 3. Look at what the model would be shown

```sh
uv run python -m network_dork context --alert-id syn-001
```

**Expect:** a JSON `AlertContext` with the alert, a 7-day window, and flow
and DNS evidence from `fixtures/zeek/`. No LLM is called.

This is the evidence-gathering half of the system in isolation.

---

## 4. Run the full pipeline with the deterministic fake model

```sh
make run-fake
```

**Expect:** 12 reports, then `Completed: 12; failures: 0`. It prints
`TEST MODE` to stderr first — the fake client never impersonates a real
model.

Run it a **second time**:

```sh
make run-fake
```

**Expect:** `Completed: 0; failures: 0`. Every alert is already terminal in
the state store, so nothing is reprocessed. That is the restart-safety
property working.

To start over: `rm -rf var/fake`.

---

## 5. Inspect the audit trail

```sh
wc -l var/fake/audit.jsonl
uv run python -c "
import json, collections
e=[json.loads(l) for l in open('var/fake/audit.jsonl')]
print(collections.Counter(x['action'] for x in e))
print(json.dumps([x for x in e if x['action']=='llm_response'][0], indent=2))
"
```

**Expect:** 144 events -- 96 `context_query`, 12 `llm_request`, 12
`llm_response`, 24 `report_write` -- and one `llm_response` record showing a
prompt hash, response hash, duration, and an `identity` block with run id,
user, host, and pid.

Prompt and response *bodies* are absent by default — they carry telemetry.
Set `NETWORK_DORK_AUDIT_RECORD_PROMPT_BODIES=true` if you want full capture.

---

## 6. Run the forecast evaluation

```sh
make eval
```

**Expect:** a threshold sweep, then a per-metric noise floor table, then:

```
At the configured per-metric thresholds:
  c2_beaconing           FOUND
  data_exfiltration      FOUND
  internal_scanning      FOUND
  benign flagged         0/8 (false positives: 0)
```

`timesfm` will report `unavailable` unless you completed step 9. That is
correct — it means no sidecar is running.

The corpus is deterministic. Regenerating it must change nothing:

```sh
md5sum fixtures/timeseries/corpus.json
uv run python scripts/generate_timeseries_corpus.py
md5sum fixtures/timeseries/corpus.json   # identical
```

Read `docs/evaluation.md` for what these numbers mean and where they are
weak.

---

## 7. Run against a real local model

Requires [Ollama](https://ollama.com).

```sh
ollama serve                          # in one terminal
ollama pull qwen2.5:3b-instruct       # ~2 GB, once
make demo-local
```

**Expect:** a `var/demo/<timestamp>/` directory containing `manifest.json`,
`reports.sqlite3`, and `audit.jsonl`, and 12 real investigations.

Read one:

```sh
uv run python -c "
import sqlite3, json, glob
db = sorted(glob.glob('var/demo/*/reports.sqlite3'))[-1]
row = sqlite3.connect(db).execute('SELECT payload FROM reports LIMIT 1').fetchone()
print(json.dumps(json.loads(row[0]), indent=2))
"
```

**Expect:** a report citing only evidence identifiers it was given, with no
claim that any action was taken. If the model produces something ungrounded,
you will see a `FailureRecord` instead of a report — that is the grounding
check doing its job, and `errors` will say exactly what it rejected.

**If a report is rejected repeatedly:** that is informative, not a bug.
`qwen2.5:3b-instruct` is small. Try `NETWORK_DORK_MODEL=qwen2.5:7b-instruct
make demo-local` and compare.

---

## 8. Try the enrichment path

The shipped fixtures deliberately have too little history to forecast, so
enrichment reports that honestly:

```sh
NETWORK_DORK_FORECAST_ADAPTER=enrichment \
  uv run python -m network_dork context --alert-id syn-001 \
  | uv run python -c "import json,sys; c=json.load(sys.stdin); \
      print('forecast records:', len(c['forecast'])); \
      print('reason:', c['unavailable'].get('forecast'))"
```

**Expect:** `0` records and `No metric had enough history to forecast`. A
host needs about 14 days of coverage before anything is forecast — guessing
from a zero-padded series is how false positives get manufactured.

To see enrichment actually fire, point it at your own Zeek `conn.log` with
real history:

```sh
NETWORK_DORK_FORECAST_ADAPTER=enrichment \
NETWORK_DORK_ZEEK_DIRECTORY=/path/to/your/zeek/logs \
  uv run python -m network_dork context --alert-id <an-alert-id>
```

---

## 9. Optional: the TimesFM sidecar

Only if you want to compare a learned forecaster. The baseline is the
default and finds all three corpus campaigns without it.

```sh
# On a machine with internet access:
uv run pip install huggingface_hub
uv run python scripts/stage_timesfm_weights.py \
    --destination ./models/timesfm-2.5-200m

docker build -t network-dork-timesfm services/timesfm/
docker run --rm -p 127.0.0.1:11435:11435 \
    -v "$PWD/models/timesfm-2.5-200m:/models/timesfm-2.5-200m:ro" \
    network-dork-timesfm

# In another terminal:
curl -s http://127.0.0.1:11435/health
make eval
```

**Expect:** `{"status":"ok","model":"timesfm-2.5-200m", ...}` from the health
check, and both forecasters scored side by side.

**Note:** TimesFM 3.x weights are licensed for non-commercial use only and
are refused by the staging script, the sidecar, and the client. Pin 2.5.

---

## 10. Verify the security boundaries yourself

These are the claims worth checking rather than believing.

**Public endpoints are refused before any connection is attempted:**

```sh
uv run python -c "
from network_dork.config import resolve_local_endpoint, LocalEndpointError
for url in ['http://127.0.0.1:11434', 'http://8.8.8.8:11434',
            'http://0177.0.0.1:11434', 'http://2130706433:11434',
            'http://127.0.0.1.nip.io:80', 'http://169.254.169.254:80']:
    try:
        print(f'ALLOW  {url:32} {resolve_local_endpoint(url).connect_url}')
    except LocalEndpointError as e:
        print(f'REFUSE {url:32} {e}')
"
```

**Expect:** only the loopback URL is allowed. The octal, decimal, DNS-rebind,
and cloud-metadata forms are all refused — no DNS lookup happens at all.

Note this check runs on the *real* run path, not `--fake`: the fake client
never constructs an Ollama client, so `NETWORK_DORK_OLLAMA_BASE_URL` is not
validated during `make run-fake`. To see it fail in the pipeline itself you
need a non-fake run:

```sh
NETWORK_DORK_OLLAMA_BASE_URL=http://8.8.8.8:11434   uv run python -m network_dork run
```

**Hostile alert identifiers cannot reach a URL:**

```sh
uv run python -c "
from network_dork.adapters.identity import normalize_alert_id
print(normalize_alert_id('zeek-notice', 'x/../../../_cluster/settings'))
print(normalize_alert_id('suricata-eve', '12345:2001219:7'))
"
```
**Expect:** the first is rewritten with a digest suffix and contains no `/`;
the second is unchanged, because ordinary identifiers stay readable.

**A broken telemetry source does not abort a batch:** covered by
`tests/test_phase1_regressions.py`; read it, it is short.

---

## Where to look when something misbehaves

| Symptom | Look at |
|---|---|
| Report rejected repeatedly | `errors` in the `FailureRecord`; the grounding rule it broke |
| No forecast evidence | `unavailable.forecast` — usually insufficient history |
| Everything flagged as anomalous | `min_score_by_metric` is below a metric's noise floor; run `make eval` |
| Alert not reprocessed | It is terminal in the state store; `rm -rf var/fake` |
| `OutcomeSchemaError` | Pre-existing database; run `scripts/migrate_outcomes.py` |
