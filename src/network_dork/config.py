"""YAML -> optional YAML overlay -> explicit environment overrides."""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

class SettingsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class AlertsSettings(SettingsModel):
    path: Path = Path("fixtures/alerts/alerts.jsonl")

class ContextSettings(SettingsModel):
    zeek_directory: Path = Path("fixtures/zeek")
    window_days: int = Field(default=7, ge=1, le=3650)

class LLMSettings(SettingsModel):
    base_url: str = "http://127.0.0.1:11434"
    model: str = Field(default="qwen2.5:3b-instruct", min_length=1)
    temperature: float = Field(default=0.0, ge=0, le=2)
    timeout_seconds: float = Field(default=120.0, gt=0, le=3600)
    max_attempts: int = Field(default=3, ge=1, le=10)

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
        if (
            self.telemetry_username
            and self.telemetry_username == self.report_username
        ):
            raise ValueError("Telemetry and report usernames must differ")
        for prefix in ("telemetry", "report"):
            username = getattr(self, f"{prefix}_username")
            password = getattr(self, f"{prefix}_password")
            if bool(username) != bool(password):
                raise ValueError(f"{prefix} username and password must be paired")
        return self

class Settings(SettingsModel):
    alerts: AlertsSettings = Field(default_factory=AlertsSettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    credentials: Credentials = Field(default_factory=Credentials)
    adapters: dict[str, dict[str, str]] = Field(default_factory=dict)

ENV_PATHS = {
    "NETWORK_DORK_ALERTS_PATH": ("alerts", "path"),
    "NETWORK_DORK_ZEEK_DIRECTORY": ("context", "zeek_directory"),
    "NETWORK_DORK_CONTEXT_WINDOW_DAYS": ("context", "window_days"),
    "NETWORK_DORK_OLLAMA_BASE_URL": ("llm", "base_url"),
    "NETWORK_DORK_MODEL": ("llm", "model"),
    "NETWORK_DORK_TEMPERATURE": ("llm", "temperature"),
    "NETWORK_DORK_TIMEOUT_SECONDS": ("llm", "timeout_seconds"),
    "NETWORK_DORK_MAX_ATTEMPTS": ("llm", "max_attempts"),
    "NETWORK_DORK_STATE_PATH": ("storage", "state_path"),
    "NETWORK_DORK_REPORTS_PATH": ("storage", "reports_path"),
    "NETWORK_DORK_AUDIT_PATH": ("storage", "audit_path"),
    "NETWORK_DORK_TELEMETRY_USERNAME": ("credentials", "telemetry_username"),
    "NETWORK_DORK_TELEMETRY_PASSWORD": ("credentials", "telemetry_password"),
    "NETWORK_DORK_REPORT_USERNAME": ("credentials", "report_username"),
    "NETWORK_DORK_REPORT_PASSWORD": ("credentials", "report_password"),
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
