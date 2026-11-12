"""Environment-backed configuration for the SOC triage agent."""

from __future__ import annotations

import os
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
    log_level: str = "INFO"

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
            "LOG_LEVEL": "log_level",
        }
        for environment_name, field_name in mapping.items():
            value = os.getenv(environment_name)
            if value is not None and value != "":
                values[field_name] = value
        return cls.model_validate(values)
