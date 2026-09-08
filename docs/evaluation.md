# Forecast evaluation

Enrichment is only worth having if it is right often enough that an analyst
keeps reading it. This document records what was actually measured, including
what does not work.

Reproduce with:

```sh
python scripts/generate_timeseries_corpus.py   # deterministic, seed 20260115
python -m network_dork eval --forecaster all
```

## The corpus

Thirty days of five-minute buckets for nine synthetic hosts
(`fixtures/timeseries/`). Three carry malicious windows, three carry *benign*
windows that look just as unusual, and three are clean.

| Host | Profile | Label |
|---|---|---|
| 10.10.0.11 | workstation, quiet | clean |
| 10.10.0.12 | workstation, high variance | clean |
| 10.10.0.13 | steady server | clean |
| 10.10.0.21 | weekly backup window | **benign** |
| 10.10.0.22 | monthly patch cycle | **benign** |
| 10.10.0.23 | host onboarded on day 20 | **benign** |
| 10.10.0.31 | low-rate C2 beaconing, day 25 | malicious |
| 10.10.0.32 | outbound volume ramp, day 27 | malicious |
| 10.10.0.33 | internal scanning, day 22 | malicious |

The benign three are the point. A corpus made only of attacks cannot show
false positives, and false positives are what destroy trust in an evidence
field. A backup window moves exactly like exfiltration.

## Result: seasonal-naive baseline

1569 evaluation points, 159 skipped for insufficient history, 15 malicious.

| Threshold | Precision | Recall | F1 | FP rate | Benign flagged |
|---:|---:|---:|---:|---:|---:|
| 4 | 0.03 | 0.67 | 0.06 | 0.217 | 2/6 |
| 8 | 0.07 | 0.53 | 0.13 | 0.066 | 2/6 |
| 16 | 0.23 | 0.47 | 0.31 | 0.015 | 2/6 |
| **24** | **1.00** | **0.27** | **0.42** | **0.000** | **0/6** |
| 32 | 1.00 | 0.27 | 0.42 | 0.000 | 0/6 |
| 64 | 1.00 | 0.07 | 0.12 | 0.000 | 0/6 |

At the shipped threshold of 24.0:

| Campaign | Outcome |
|---|---|
| internal scanning | **found** |
| data exfiltration | **found** |
| C2 beaconing | **missed** |
| benign windows flagged | 0 of 6 |

## What this means

**The threshold is the whole design.** The first run used a threshold of 1.0
and produced precision 0.01 with a 64% false-positive rate — it flagged
almost everything. That is not a subtle failure: at that setting every
investigation would carry an "anomaly", and an analyst would learn within a
day to ignore the field.

The cause is structural, not a bug. An 80% forecast band leaves roughly a
fifth of buckets outside it *by construction*, so "outside the band" is an
ordinary event. On this corpus a benign window still peaks around 2.6, and
the 99th percentile of benign peaks is 16.2. Anything below about 20 is
noise. `forecast.min_score` defaults to 24.0 for that reason, and enrichment
emits no evidence at all below it.

**Beaconing is invisible to this baseline, and that is expected.** Its peak
scores (2.8 to 20.1) sit inside the benign distribution, because low-rate
beaconing is not a *volume* anomaly. It is a *periodicity* anomaly: regular
small callbacks at a fixed interval. Seasonal-naive compares magnitude
against the same time yesterday and has no way to see regularity.

This is the concrete, measurable gap a learned forecaster could close, and
it is the specific claim TimesFM has to beat:

> Detect the day-25 beaconing window on 10.10.0.31 while still flagging zero
> of the six benign windows.

If TimesFM cannot do that, it is adding roughly 2–3 GB of dependencies and a
second runtime for two attack classes the baseline already finds at
precision 1.00. Run `--forecaster all` to compare directly.

## Honest limits of this result

- **The corpus is synthetic.** It was written to be realistic, not to be
  real. Numbers here justify design decisions; they do not predict field
  performance.
- **Nine hosts and three campaigns** is a small sample. A single evaluation
  point moving changes recall by 0.07.
- **The threshold is tuned on the same corpus it is evaluated on.** With
  this few labels there is no meaningful holdout. Treat 24.0 as a starting
  point to re-tune on your own telemetry, not as a validated constant.
- **`min_observations` (100) and `min_span_fraction` (0.5)** were chosen by
  judgement, not measurement. They control which hosts are forecast at all.
- **Recall is per evaluation point**, so it understates operational value:
  windows that clip the edge of an attack cannot be detected and should not
  be. The per-campaign table is the number that matters.

## Why zero false positives matters more than recall here

This is enrichment, not detection. Missing the beaconing window costs
nothing that was not already lost — the alert still gets investigated with
flows, DNS, auth, and prior-alert context, exactly as before enrichment
existed. But flagging the backup window would put a false "anomalous" claim
in front of an analyst on a real investigation.

An enrichment field that is silent when it has nothing to say is useful. One
that cries wolf is worse than no field at all. That asymmetry is why the
shipped threshold favours precision so heavily.
