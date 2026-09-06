# Synthetic fixture corpus

Every fixture in this directory was authored for network dork.
None was derived from a public capture or an actual organization.
Scenario labels describe author intent, not a proven inference from
these deliberately small telemetry samples.

Network addresses use private or documentation ranges. DNS names use
the reserved `.test` suffix. All event times are fixed, timezone-aware
UTC timestamps, independent of the current clock.

`alerts/alerts.jsonl` contains normalized, pre-existing alert examples.
Reading these examples is not detection. Production-format Suricata,
Zeek notice, and OpenSearch samples belong to the adapter phase.

`zeek/conn.log` and `zeek/dns.log` use Zeek's JSON logging form.
`zeek/auth.log` is a documented synthetic normalized authentication
export, not a claim that stock Zeek emits a generic auth.log.
Its fields are: ts (Unix seconds), host, src_ip, user, service, result.

Ground truth is kept separately in `ground_truth.yaml` and must never
enter the model prompt. Each NIST mapping is one reference label for
evaluating this synthetic scenario; NIST controls are not unique
attack classifications.

| Alert | Origin | Authored scenario |
|---|---|---|
| syn-001 | Synthetic | Existing alert for periodic HTTP callback traffic |
| syn-002 | Synthetic | Existing alert for periodic HTTPS callback traffic |
| syn-003 | Synthetic | Existing alert for encoded-looking DNS queries |
| syn-004 | Synthetic | Existing alert for DNS TXT channel activity |
| syn-005 | Synthetic | Existing alert for outbound HTTPS data transfer |
| syn-006 | Synthetic | Existing alert for outbound transfer to another endpoint |
| syn-007 | Synthetic | Existing alert involving SMB administrative access |
| syn-008 | Synthetic | Existing alert involving RDP access |
| syn-009 | Synthetic | Existing alert involving remote SSH access |
| syn-010 | Synthetic | Approved workstation update check, intent not obvious from flow |
| syn-011 | Synthetic | Approved backup transfer, intent not obvious from flow |
| syn-012 | Synthetic | Approved inventory scan, intent not obvious from flow |

Each alert has three matching connections, one DNS record, and one
authentication record. These are retrieval fixtures, not sufficiently
rich evidence to demand high-confidence malicious conclusions.
Benign labels represent author-known intent; conservative uncertainty
or a null technique is the desired behavior when context is insufficient.
