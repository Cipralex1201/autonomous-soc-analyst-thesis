"""Environment-backed configuration for the SOC triage agent."""

from __future__ import annotations

import os
from fnmatch import fnmatchcase
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator


class Settings(BaseModel):
    """Validated settings used by the Elasticsearch milestones."""

    elastic_url: str = "https://localhost:9200"
    elastic_api_key: str | None = None
    elastic_ca_cert: str | None = None
    elastic_alert_index: str = ".alerts-security.alerts-default"
    elastic_telemetry_indices: str = "logs-*"
    elastic_nginx_index: str = "logs-nginx.access-*"
    poll_interval_seconds: float = Field(default=5, gt=0)
    max_query_results: int = Field(default=100, gt=0, le=1000)
    max_query_window_minutes: int = Field(default=30, gt=0, le=1440)
    max_tool_result_bytes: int = Field(default=20000, gt=1000, le=1_000_000)
    elastic_search_timeout_seconds: int = Field(default=10, gt=0, le=120)
    max_alert_field_text_length: int = Field(default=4000, gt=100, le=100000)
    max_alert_evidence_fields: int = Field(default=200, gt=10, le=1000)
    log_level: str = "INFO"
    openai_api_key: str | None = None
    openai_model: str | None = None
    prompt_inspection_mode: str = "off"
    log_llm_requests: bool = False
    log_llm_responses: bool = False
    log_tool_calls: bool = False
    log_tool_results: bool = False
    log_triage_results: bool = False
    max_tool_calls: int = Field(default=5, gt=0, le=100)
    max_model_requests: int = Field(default=8, gt=0, le=100)

    @field_validator("elastic_url")
    @classmethod
    def require_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("ELASTIC_URL must use http:// or https://")
        return value.rstrip("/")

    @field_validator("elastic_alert_index", "elastic_telemetry_indices", "elastic_nginx_index")
    @classmethod
    def require_index_pattern(cls, value: str) -> str:
        if not value.strip() or any(char in value for char in "\r\n"):
            raise ValueError("Elasticsearch index patterns must be non-empty and single-line")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
        return normalized

    @field_validator("prompt_inspection_mode")
    @classmethod
    def validate_prompt_inspection_mode(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"off", "log", "pause"}:
            raise ValueError("PROMPT_INSPECTION_MODE must be off, log, or pause")
        return normalized

    @classmethod
    def from_env(cls, env_file: str | Path | None = None) -> "Settings":
        """Load a dotenv file, then apply environment variables."""
        load_dotenv(env_file or ".env", override=False)
        values: dict[str, object] = {}
        mapping = {
            "ELASTIC_URL": "elastic_url",
            "ELASTIC_API_KEY": "elastic_api_key",
            "ELASTIC_CA_CERT": "elastic_ca_cert",
            "ELASTIC_ALERT_INDEX": "elastic_alert_index",
            "ELASTIC_TELEMETRY_INDICES": "elastic_telemetry_indices",
            "ELASTIC_NGINX_INDEX": "elastic_nginx_index",
            "POLL_INTERVAL_SECONDS": "poll_interval_seconds",
            "MAX_QUERY_RESULTS": "max_query_results",
            "MAX_QUERY_WINDOW_MINUTES": "max_query_window_minutes",
            "MAX_TOOL_RESULT_BYTES": "max_tool_result_bytes",
            "ELASTIC_SEARCH_TIMEOUT_SECONDS": "elastic_search_timeout_seconds",
            "MAX_ALERT_FIELD_TEXT_LENGTH": "max_alert_field_text_length",
            "MAX_ALERT_EVIDENCE_FIELDS": "max_alert_evidence_fields",
            "LOG_LEVEL": "log_level",
            "OPENAI_API_KEY": "openai_api_key",
            "OPENAI_MODEL": "openai_model",
            "PROMPT_INSPECTION_MODE": "prompt_inspection_mode",
            "LOG_LLM_REQUESTS": "log_llm_requests",
            "LOG_LLM_RESPONSES": "log_llm_responses",
            "LOG_TOOL_CALLS": "log_tool_calls",
            "LOG_TOOL_RESULTS": "log_tool_results",
            "LOG_TRIAGE_RESULTS": "log_triage_results",
            "MAX_TOOL_CALLS": "max_tool_calls",
            "MAX_MODEL_REQUESTS": "max_model_requests",
        }
        for environment_name, field_name in mapping.items():
            value = os.getenv(environment_name)
            if value is not None and value != "":
                values[field_name] = value
        return cls.model_validate(values)


def configured_index_patterns(settings: Settings) -> tuple[str, ...]:
    """Return the configured Elasticsearch scopes in stable order."""
    return tuple(dict.fromkeys((
        settings.elastic_telemetry_indices,
        settings.elastic_nginx_index,
        settings.elastic_alert_index,
    )))


def is_configured_index(settings: Settings, index: str) -> bool:
    """Allow configured patterns or concrete indices matched by those patterns."""
    if index in configured_index_patterns(settings):
        return True
    if any(character in index for character in "*?["):
        return False
    return any(fnmatchcase(index, pattern) for pattern in configured_index_patterns(settings))


def index_authorization_error(settings: Settings, index: str) -> str:
    permitted = ", ".join(configured_index_patterns(settings))
    return (
        f"index {index!r} is not authorized; permitted index patterns: {permitted}"
    )
