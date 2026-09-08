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

## A correction to an earlier version of this corpus

The first corpus modelled beaconing as a seven-fold volume bump with ordinary
variance. Measured, its coefficient of variation during the "beacon" window
was 0.337 against 0.292 on a clean host -- statistically indistinguishable.
It was not beaconing at all, so the earlier conclusion "beaconing is missed"
really meant "a modest volume bump is missed", which is a much weaker claim.

Beaconing is now modelled as what it is: a fixed callback interval that
ignores the working day. Its CV in the window is 0.032 against 0.301 on a
normal day for the same host.

## Result: seasonal-naive baseline

2092 evaluation points, 212 skipped for insufficient history, 20 malicious.

### One global threshold

| Threshold | Precision | Recall | FP rate | Benign flagged |
|---:|---:|---:|---:|---:|
| 4 | 0.03 | 0.60 | 0.160 | 2/8 |
| 16 | 0.21 | 0.30 | 0.011 | 2/8 |
| 24 | 1.00 | 0.20 | 0.000 | 0/8 |
| 64 | 1.00 | 0.05 | 0.000 | 0/8 |

Zero false positives, but **beaconing is missed at every setting.**

### Why one threshold cannot work

Each metric has its own benign noise floor, and they are nowhere near each
other:

| Metric | Benign maximum | Malicious peaks |
|---|---:|---|
| conn_regularity | 3.47 | 9.4, 12.2 |
| conn_count | 7.54 | 12.5, 13.2, 59.4 |
| distinct_destinations | 19.50 | 166.2 |
| bytes_out | 22.36 | 36.1, 50.8 |

A single bar has to clear 22.36 to avoid false positives from `bytes_out`,
which buries `conn_regularity` entirely -- its signal peaks at 12.2, a third
of the bar it is forced to clear, despite standing more than three times
above its own noise floor.

### Per-metric thresholds (shipped)

`forecast.min_score_by_metric` sets each metric above its own floor:

| Metric | Threshold | Benign floor |
|---|---:|---:|
| conn_count | 10.0 | 7.54 |
| bytes_out | 25.0 | 22.36 |
| distinct_destinations | 25.0 | 19.50 |
| conn_regularity | 4.0 | 3.47 |

| Campaign | Outcome |
|---|---|
| internal scanning | **found** |
| data exfiltration | **found** |
| C2 beaconing | **found** |
| benign windows flagged | **0 of 8** |

All three campaigns, still with zero false positives.

Confirmed end to end through the enrichment provider:

```
10.10.0.11  workstation-quiet  (clean)             0 records
10.10.0.12  workstation-noisy  (clean)             0 records
10.10.0.21  backup-host        (BENIGN spike)      0 records
10.10.0.31  beacon-host        (MALICIOUS)        10 records  conn_count, conn_regularity
10.10.0.32  exfil-host         (MALICIOUS)         5 records  bytes_out
10.10.0.33  scan-host          (MALICIOUS)        15 records  bytes_out, conn_count, distinct_destinations
```

## What this means

**The thresholds are the whole design.** The first run used a single
threshold of 1.0 and produced precision 0.01 with a 64% false-positive rate.
That is not a subtle failure: every investigation would have carried an
"anomaly", and an analyst would have learned within a day to ignore the
field.

The cause is structural, not a bug. An 80% forecast band leaves roughly a
fifth of buckets outside it *by construction*, so "outside the band" is an
ordinary event rather than a finding. Raising the bar to 24 fixed the false
positives, and then hid beaconing, because one number cannot serve four
metrics whose noise floors span 3.5 to 22.4. Each metric now carries its own
threshold, and enrichment emits nothing below it.

**Beaconing needed a different measurement, not a bigger model.** Low-rate
beaconing is not a volume anomaly; it is a rhythm. No forecaster of
magnitude encodes rhythm, however good it is, so a larger model was the
wrong instrument. `conn_regularity` -- the reciprocal of the coefficient of
variation over a trailing hour -- carries the signal directly, in pure
Python, with no new dependencies, and flows through the same
forecast-and-score path as every other metric.

**What this leaves for TimesFM.** All three campaigns are now found at
precision 1.00 with the baseline. The remaining case for a learned
forecaster is narrower but real: it would have to compress the benign noise
floors, letting thresholds drop and catching attacks weaker than the ones
here. That is a genuine possibility on messy real telemetry, where these
floors will be higher than a synthetic corpus suggests. It is not
demonstrated, and until it is, TimesFM stays available and off by default.
Run `--forecaster all` to compare once a sidecar is running.

## Honest limits of this result

- **The corpus is synthetic.** It was written to be realistic, not to be
  real. Numbers here justify design decisions; they do not predict field
  performance.
- **Nine hosts and three campaigns** is a small sample. A single evaluation
  point moving changes recall by 0.07.
- **The thresholds are tuned on the same corpus they are evaluated on.**
  With eight benign windows there is no meaningful holdout, and each
  threshold sits just above a benign maximum estimated from very few
  samples. Treat them as starting points to re-derive on your own
  telemetry, not as validated constants. `python -m network_dork eval`
  prints each metric's measured floor next to its configured threshold and
  marks any that is too low.
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
