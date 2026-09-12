# Running on real telemetry

Two things this answers: how to demonstrate the forecast path on a capture
you took this afternoon, and how to collect a baseline worth trusting.

Keep them straight when you present. The first shows the mechanism runs on
real packets. Only the second is evidence about traffic.

## 1. One capture, right now

```sh
cd ~/network-dork && mkdir -p var/real
sudo tcpdump -i en0 -w var/real/real.pcap     # Ctrl-C when done
cd var/real
sudo suricata-update            # once
suricata -r real.pcap -l .
zeek -r real.pcap LogAscii::use_json=T        # JSON is required
grep -c '"event_type":"alert"' eve.json
```

Real Suricata alerts from real ET Open rules, real Zeek telemetry. Investigate
them:

```sh
cd ~/network-dork
NETWORK_DORK_ALERT_ADAPTER=suricata_eve \
NETWORK_DORK_ALERTS_PATH=var/real/eve.json \
NETWORK_DORK_ZEEK_DIRECTORY=var/real \
NETWORK_DORK_TIMEOUT_SECONDS=600 \
uv run python -m network_dork run --config config/default.yaml
```

Real Zeek produces no `auth.log`, so auth context reports unavailable. That
is handled, and the prompt covers missing telemetry.

## 2. The forecast path on that same capture

`readiness` will refuse: the shipped window is fourteen days at five-minute
buckets and needs a span of at least seven. That default is correct and
should stay.

The requirements are relative, though -- enough buckets, spanning enough of
the requested window -- so a shorter bucket over a shorter history satisfies
the same arithmetic:

```sh
uv run python scripts/suggest_forecast_window.py \
    --conn-log var/real/conn.log \
    --write-overlay config/demo-short-window.yaml
```

It measures the capture, prints the settings that fit it, and refuses if
there are too few buckets to separate history from anomaly. Then:

```sh
make timesfm-local          # in another terminal, if you want TimesFM

NETWORK_DORK_ZEEK_DIRECTORY=var/real \
NETWORK_DORK_FORECAST_ADAPTER=enrichment \
NETWORK_DORK_FORECASTER_ADAPTER=timesfm \
uv run python -m network_dork readiness --config config/demo-short-window.yaml

NETWORK_DORK_ALERT_ADAPTER=suricata_eve \
NETWORK_DORK_ALERTS_PATH=var/real/eve.json \
NETWORK_DORK_ZEEK_DIRECTORY=var/real \
NETWORK_DORK_FORECAST_ADAPTER=enrichment \
NETWORK_DORK_FORECASTER_ADAPTER=timesfm \
NETWORK_DORK_TIMEOUT_SECONDS=600 \
uv run python -m network_dork trace --alert-id <id> \
    --config config/demo-short-window.yaml
```

Stage 3 of `trace` then carries forecast evidence produced by TimesFM from
your own packets.

**Say what this is.** The mechanism works end to end on real telemetry: real
bucketing, real forecast, real deviation scores, real evidence in the
prompt. It is not a baseline. Fourteen days of a host's behaviour tells you
what is normal for that host; twenty minutes tells you what it did for
twenty minutes. Quote it as the pipeline working, never as a detection rate,
and do not deploy the overlay.

## 3. Collecting a baseline that is worth trusting

Each Zeek restart writes a fresh log set, and a laptop restarts whenever it
sleeps or changes network. So capture into one directory per session and
merge them:

```sh
mkdir -p ~/network-dork/var/live/session-$(date +%Y%m%dT%H%M%S)
cd ~/network-dork/var/live/session-*        # the one just created
sudo nohup zeek -i en0 LogAscii::use_json=T > zeek.out 2>&1 &
```

Start a new session directory whenever capture stops. Before each run:

```sh
cd ~/network-dork
uv run python scripts/merge_zeek_sessions.py
```

It concatenates every session in timestamp order, drops byte-identical
duplicate lines so re-running is safe, and prints the merged span against
the seven-day minimum. When it says the span clears:

```sh
NETWORK_DORK_ZEEK_DIRECTORY=var/live/merged \
NETWORK_DORK_FORECAST_ADAPTER=enrichment \
uv run python -m network_dork readiness
```

No overlay, no caveat, and `python -m network_dork eval --forecaster all`
becomes a comparison on your own traffic rather than on a generated corpus.
