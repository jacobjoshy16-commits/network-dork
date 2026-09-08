# Your testing loop

Four commands. Everything else in this repo exists to support them.

## 1. Build a network to test against

```sh
python scripts/make_sample_network.py --destination var/sample

export NETWORK_DORK_ALERTS_PATH=var/sample/alerts.jsonl
export NETWORK_DORK_ZEEK_DIRECTORY=var/sample/zeek
export NETWORK_DORK_FORECAST_ADAPTER=enrichment
```

Twenty days of connection logs for four hosts and three alerts. One host
beacons, one exfiltrates, one is entirely ordinary. The third is the
important one: it is how you find out whether the engine cries wolf.

Point the same variables at your own Zeek logs when you have them.

## 2. Watch one alert go through

```sh
python -m network_dork trace --alert-id sample-beacon --fake
```

Seven numbered stages: the alert, the evidence gathered, what the forecaster
contributed, what the model was asked, what it answered, which checks passed,
and the brief an analyst reads. Nothing is written, so run it as often as you
like.

**This is the command for understanding the engine.** Run it on all three
sample alerts and compare.

Add `--show-prompt` to see the literal text the model receives.

## 3. Judge the answer

Read stage 7 and ask three questions:

1. **Would this help an analyst?** If it restates the alert without adding
   anything, the evidence gathering is the problem, not the model.
2. **Is everything in it supported?** Every entity named should appear in
   stage 2 or 3. If not, that is a bug in the grounding checks.
3. **Did the forecaster help or distract?** Compare `sample-beacon` against
   `sample-quiet`. The quiet host should produce **no** forecast evidence.

## 4. Change one thing and re-measure

```sh
python -m network_dork eval          # forecaster accuracy, on labelled data
make test                            # nothing else broke
```

`eval` is the honest scorekeeper: it reports whether each attack was found
*and* whether any benign window was flagged. A change that finds more attacks
while flagging benign windows is a bad change.

## What to change first

| If you see | Turn |
|---|---|
| Anomalies on ordinary hosts | `forecast.min_score_by_metric` up |
| Real anomalies missed | `forecast.min_score_by_metric` down, then re-run `eval` |
| "No metric had enough history" | Collect longer, or lower `forecast.min_observations` |
| Reports too vague | `context.max_records` up, and `llm.num_ctx` with it |
| Reports rejected repeatedly | Read `errors` — the grounding rule it broke is named |
| Nothing forecast at all | `python -m network_dork readiness` |

After **any** change, run `python -m network_dork eval`. If false positives
went up, the change was not worth it however good it looked.

## Two things worth knowing

**Run `trace` on realistic data, not just the fixtures.** Two real bugs were
found this way and neither showed up in the unit tests: a forecast band that
collapsed to zero width on hosts that are quiet overnight, and an audit file
format that could not be extended. Generated data with a full daily rhythm
exercises paths that small fixtures never reach.

**A fix that looks obviously right can make accuracy worse.** Clamping the
forecast band at zero — because a negative connection count is impossible —
narrowed the band, raised every score, and took the evaluation corpus from
zero false positives to seven. It is now clamped for display only. Measure
before you keep a change.
