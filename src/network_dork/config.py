"""Layered settings and local-only endpoint resolution.

Configuration and adapter references are trusted operator input.
Alert contents and model output must never modify them.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class SettingsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertsSettings(SettingsModel):
    path: Path = Path("fixtures/alerts/alerts.jsonl")


class ContextSettings(SettingsModel):
    zeek_directory: Path = Path("fixtures/zeek")
    window_days: int = Field(default=7, ge=1, le=3650)
    # Caps evidence per kind so a busy host cannot push the prompt past the
    # model's input budget. Most recent records are kept.
    #
    # An evidence record costs roughly 380 characters of prompt. With the
    # shipped llm.num_ctx of 8192 (llm.max_input_chars 32000) about 74
    # records fit in total, so 15 per kind across four kinds leaves margin.
    # Raise llm.num_ctx and llm.max_input_chars together before raising this.
    max_records: int = Field(default=15, ge=1, le=10000)


class LLMSettings(SettingsModel):
    base_url: str = "http://127.0.0.1:11434"
    model: str = Field(default="qwen2.5:3b-instruct", min_length=1)
    temperature: float = Field(default=0.0, ge=0, le=2)
    timeout_seconds: float = Field(default=120.0, gt=0, le=3600)
    max_attempts: int = Field(default=3, ge=1, le=10)
    num_ctx: int = Field(default=8192, ge=2048, le=32768)
    num_predict: int = Field(default=2048, ge=256, le=8192)
    max_input_chars: int = Field(default=32000, ge=1024, le=500000)
    max_response_bytes: int = Field(default=1048576, ge=1024, le=8388608)


class ForecastSettings(SettingsModel):
    """Enrichment geometry.

    history_buckets is the quality knob: a forecaster is only as good as the
    history it is shown, and 14 days at five-minute buckets is the point where
    daily and weekly rhythm becomes visible. horizon_buckets is the pre-alert
    window that gets scored.
    """

    bucket_seconds: int = Field(default=300, ge=60, le=86400)
    history_buckets: int = Field(default=4032, ge=2, le=16000)
    horizon_buckets: int = Field(default=72, ge=1, le=1024)
    period_buckets: int = Field(default=288, ge=2, le=16000)
    max_evidence: int = Field(default=5, ge=1, le=50)
    # Deviation score a bucket must reach to become evidence, used for any
    # metric without its own entry below.
    min_score: float = Field(default=24.0, ge=0, le=10000)
    # Metrics have very different noise floors, so one global threshold is
    # set by the noisiest of them and buries the quietest. On the evaluation
    # corpus the benign maximum ranges from 3.5 (conn_regularity) to 22.4
    # (bytes_out); a single bar at 24 hid the beaconing signal completely.
    # Each value sits above that metric's own benign maximum with margin.
    # Re-derive these on real telemetry: see docs/evaluation.md.
    min_score_by_metric: dict[str, float] = Field(
        default_factory=lambda: {
            "conn_count": 10.0,
            "bytes_out": 25.0,
            "distinct_destinations": 25.0,
            "conn_regularity": 4.0,
        }
    )
    # Guards against forecasting a zero-padded series for a host with too
    # little real history.
    min_observations: int = Field(default=100, ge=1, le=1000000)
    min_span_fraction: float = Field(default=0.5, gt=0, le=1)
    base_url: str = "http://127.0.0.1:11435"
    timeout_seconds: float = Field(default=60.0, gt=0, le=3600)
    max_response_bytes: int = Field(default=4194304, ge=1024, le=33554432)


class OpenSearchSettings(SettingsModel):
    base_url: str = "http://127.0.0.1:9200"
    alerts_index: str = Field(default="security-alerts-*", min_length=1)
    flows_index: str = Field(default="network-flows-*", min_length=1)
    dns_index: str = Field(default="dns-*", min_length=1)
    auth_index: str = Field(default="auth-*", min_length=1)
    reports_index: str = Field(default="network-dork-reports", min_length=1)
    timeout_seconds: float = Field(default=30.0, gt=0, le=3600)
    max_hits: int = Field(default=500, ge=1, le=5000)
    max_response_bytes: int = Field(default=1048576, ge=1024, le=8388608)


class AgentSettings(SettingsModel):
    """What this agent is, as told to the model and shown to operators.

    Identity is a deployment fact: an analyst should be able to tell whether
    a report came from the enclave's investigator or a laboratory copy. The
    core rules -- investigates rather than detects, cannot act, treats
    evidence as untrusted -- are not settable here on purpose. A deployment
    able to edit them could turn the investigator into something else while
    the audit trail still said network-dork.
    """

    name: str = Field(default="network-dork", min_length=1, max_length=128)
    role: str = Field(default="SOC analyst assistant", min_length=1, max_length=256)
    # Free text describing where this instance runs, e.g. an enclave name.
    deployment: str = Field(default="", max_length=512)
    # Local conventions only. Appended after the fixed rules and framed to the
    # model as unable to relax them.
    additional_guidance: str = Field(default="", max_length=4000)


class AuditSettings(SettingsModel):
    # Prompts and model responses embed telemetry. Full-body capture is a
    # deliberate deployment choice, not the default.
    record_prompt_bodies: bool = False


class StorageSettings(SettingsModel):
    state_path: Path = Path("var/state.sqlite3")
    reports_path: Path = Path("var/reports.sqlite3")
    audit_path: Path = Path("var/audit.jsonl")


class Credentials(SettingsModel):
    telemetry_username: str | None = None
    telemetry_password: SecretStr | None = None
    report_username: str | None = None
    report_password: SecretStr | None = None

    @model_validator(mode="after")
    def separate_identities(self) -> "Credentials":
        if self.telemetry_username and self.telemetry_username == self.report_username:
            raise ValueError("Telemetry and report usernames must differ")
        for prefix in ("telemetry", "report"):
            username = getattr(self, f"{prefix}_username")
            password = getattr(self, f"{prefix}_password")
            if bool(username) != bool(password):
                raise ValueError(f"{prefix} username and password must be paired")
        return self


class AdapterDefinition(SettingsModel):
    class_path: str = Field(min_length=3)
    options: dict[str, Any] = Field(default_factory=dict)


class RuntimeSettings(SettingsModel):
    alert_adapter: str = "file"
    context_adapter: str = "zeek_logs"
    llm_adapter: str = "ollama"
    sink_adapter: str = "sqlite"
    # Enrichment is opt-in. Unset means the investigation path is unchanged.
    forecast_adapter: str | None = None
    timeseries_adapter: str = "zeek_buckets"
    forecaster_adapter: str = "baseline"


class Settings(SettingsModel):
    alerts: AlertsSettings = Field(default_factory=AlertsSettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    opensearch: OpenSearchSettings = Field(default_factory=OpenSearchSettings)
    forecast: ForecastSettings = Field(default_factory=ForecastSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    credentials: Credentials = Field(default_factory=Credentials)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    adapters: dict[str, dict[str, str | AdapterDefinition]] = Field(
        default_factory=dict
    )


ENV_PATHS = {
    "NETWORK_DORK_ALERTS_PATH": ("alerts", "path"),
    "NETWORK_DORK_ZEEK_DIRECTORY": ("context", "zeek_directory"),
    "NETWORK_DORK_CONTEXT_WINDOW_DAYS": ("context", "window_days"),
    "NETWORK_DORK_CONTEXT_MAX_RECORDS": ("context", "max_records"),
    "NETWORK_DORK_OLLAMA_BASE_URL": ("llm", "base_url"),
    "NETWORK_DORK_MODEL": ("llm", "model"),
    "NETWORK_DORK_TEMPERATURE": ("llm", "temperature"),
    "NETWORK_DORK_TIMEOUT_SECONDS": ("llm", "timeout_seconds"),
    "NETWORK_DORK_MAX_ATTEMPTS": ("llm", "max_attempts"),
    "NETWORK_DORK_NUM_CTX": ("llm", "num_ctx"),
    "NETWORK_DORK_NUM_PREDICT": ("llm", "num_predict"),
    "NETWORK_DORK_MAX_INPUT_CHARS": ("llm", "max_input_chars"),
    "NETWORK_DORK_MAX_RESPONSE_BYTES": ("llm", "max_response_bytes"),
    "NETWORK_DORK_OPENSEARCH_BASE_URL": ("opensearch", "base_url"),
    "NETWORK_DORK_OPENSEARCH_ALERTS_INDEX": ("opensearch", "alerts_index"),
    "NETWORK_DORK_OPENSEARCH_FLOWS_INDEX": ("opensearch", "flows_index"),
    "NETWORK_DORK_OPENSEARCH_DNS_INDEX": ("opensearch", "dns_index"),
    "NETWORK_DORK_OPENSEARCH_AUTH_INDEX": ("opensearch", "auth_index"),
    "NETWORK_DORK_OPENSEARCH_REPORTS_INDEX": ("opensearch", "reports_index"),
    "NETWORK_DORK_OPENSEARCH_TIMEOUT_SECONDS": (
        "opensearch",
        "timeout_seconds",
    ),
    "NETWORK_DORK_OPENSEARCH_MAX_HITS": ("opensearch", "max_hits"),
    "NETWORK_DORK_OPENSEARCH_MAX_RESPONSE_BYTES": (
        "opensearch",
        "max_response_bytes",
    ),
    "NETWORK_DORK_AGENT_NAME": ("agent", "name"),
    "NETWORK_DORK_AGENT_ROLE": ("agent", "role"),
    "NETWORK_DORK_AGENT_DEPLOYMENT": ("agent", "deployment"),
    "NETWORK_DORK_AGENT_GUIDANCE": ("agent", "additional_guidance"),
    "NETWORK_DORK_AUDIT_RECORD_PROMPT_BODIES": (
        "audit",
        "record_prompt_bodies",
    ),
    "NETWORK_DORK_STATE_PATH": ("storage", "state_path"),
    "NETWORK_DORK_REPORTS_PATH": ("storage", "reports_path"),
    "NETWORK_DORK_AUDIT_PATH": ("storage", "audit_path"),
    "NETWORK_DORK_TELEMETRY_USERNAME": ("credentials", "telemetry_username"),
    "NETWORK_DORK_TELEMETRY_PASSWORD": ("credentials", "telemetry_password"),
    "NETWORK_DORK_REPORT_USERNAME": ("credentials", "report_username"),
    "NETWORK_DORK_REPORT_PASSWORD": ("credentials", "report_password"),
    "NETWORK_DORK_ALERT_ADAPTER": ("runtime", "alert_adapter"),
    "NETWORK_DORK_CONTEXT_ADAPTER": ("runtime", "context_adapter"),
    "NETWORK_DORK_LLM_ADAPTER": ("runtime", "llm_adapter"),
    "NETWORK_DORK_SINK_ADAPTER": ("runtime", "sink_adapter"),
    "NETWORK_DORK_FORECAST_ADAPTER": ("runtime", "forecast_adapter"),
    "NETWORK_DORK_TIMESERIES_ADAPTER": ("runtime", "timeseries_adapter"),
    "NETWORK_DORK_FORECASTER_ADAPTER": ("runtime", "forecaster_adapter"),
    "NETWORK_DORK_FORECAST_BASE_URL": ("forecast", "base_url"),
    "NETWORK_DORK_FORECAST_BUCKET_SECONDS": ("forecast", "bucket_seconds"),
    "NETWORK_DORK_FORECAST_HISTORY_BUCKETS": ("forecast", "history_buckets"),
    "NETWORK_DORK_FORECAST_HORIZON_BUCKETS": ("forecast", "horizon_buckets"),
    "NETWORK_DORK_FORECAST_PERIOD_BUCKETS": ("forecast", "period_buckets"),
}


def read_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a YAML mapping")
    return value


def merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(
    path: Path | None = None,
    *,
    defaults: Path = Path("config/default.yaml"),
    environ: Mapping[str, str] | None = None,
) -> Settings:
    env = os.environ if environ is None else environ
    data = read_yaml(defaults)
    override = path
    if override is None and env.get("NETWORK_DORK_CONFIG"):
        override = Path(env["NETWORK_DORK_CONFIG"])
    if override is not None:
        data = merge(data, read_yaml(override))
    for variable, (section, key) in ENV_PATHS.items():
        if variable in env and env[variable] != "":
            existing = data.setdefault(section, {})
            if not isinstance(existing, dict):
                raise ValueError(f"{section} must be a mapping")
            existing[key] = env[variable]
    return Settings.model_validate(data)


LOCAL_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)


class LocalEndpointError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedLocalEndpoint:
    connect_url: str
    host_header: str
    server_hostname: str


def _allowed_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise LocalEndpointError("Invalid endpoint IP address") from exc
    if getattr(address, "ipv4_mapped", None) is not None:
        raise LocalEndpointError("IPv4-mapped IPv6 endpoints are not allowed")
    if not any(
        address.version == network.version and address in network
        for network in LOCAL_NETWORKS
    ):
        raise LocalEndpointError(
            "Endpoint must use loopback, RFC 1918 IPv4, or IPv6 ULA"
        )
    return address


def resolve_local_endpoint(
    base_url: str,
    *,
    hosts_path: Path = Path("/etc/hosts"),
) -> ResolvedLocalEndpoint:
    """Resolve without DNS, then pin the connection to a numeric IP."""
    if (
        not base_url
        or any(character.isspace() for character in base_url)
        or "\\" in base_url
        or "%" in base_url
        or "?" in base_url
        or "#" in base_url
    ):
        raise LocalEndpointError("Invalid local endpoint URL")
    try:
        parsed = urlsplit(base_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LocalEndpointError("Invalid local endpoint URL") from exc

    if parsed.scheme not in {"http", "https"}:
        raise LocalEndpointError("Only HTTP and HTTPS endpoints are allowed")
    if not host or parsed.username is not None or parsed.password is not None:
        raise LocalEndpointError("Endpoint must not contain credentials")
    if parsed.path not in {"", "/"}:
        raise LocalEndpointError("Endpoint must not contain a URL path")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise LocalEndpointError("Invalid endpoint port")

    normalized_host = host.rstrip(".").lower()
    try:
        numeric = ipaddress.ip_address(normalized_host)
    except ValueError:
        numeric = None

    if numeric is not None:
        addresses = [_allowed_address(str(numeric))]
    elif normalized_host == "localhost":
        addresses = [_allowed_address("127.0.0.1")]
    else:
        if not normalized_host.isascii():
            raise LocalEndpointError("Endpoint hostnames must be ASCII")
        matches: list[str] = []
        try:
            lines = hosts_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise LocalEndpointError(
                "Cannot resolve local hostname through hosts file"
            ) from exc
        for line in lines:
            fields = line.split("#", 1)[0].split()
            if len(fields) < 2:
                continue
            aliases = {alias.rstrip(".").lower() for alias in fields[1:]}
            if normalized_host in aliases:
                matches.append(fields[0])
        if not matches:
            raise LocalEndpointError(
                "Hostname is not in the hosts file; DNS lookup is disabled"
            )
        addresses = [_allowed_address(value) for value in matches]

    addresses.sort(key=lambda address: (address.version, int(address)))
    chosen = addresses[0]
    numeric_authority = f"[{chosen}]" if chosen.version == 6 else str(chosen)
    hostname_authority = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    return ResolvedLocalEndpoint(
        connect_url=f"{parsed.scheme}://{numeric_authority}:{port}",
        host_header=f"{hostname_authority}:{port}",
        server_hostname=normalized_host,
    )
