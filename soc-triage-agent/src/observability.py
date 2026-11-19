"""Sanitized request inspection and structured investigation logging."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from collections.abc import Mapping
from pathlib import Path
from typing import Any


_SECRET_KEY = re.compile(r"(api[_-]?key|authorization|cookie|password|token|secret)", re.I)


def sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: "[REDACTED]" if _SECRET_KEY.search(str(key)) else sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", value)
    return value


def inspect_request(payload: Mapping[str, Any], mode: str, logger: logging.Logger) -> None:
    if mode == "log":
        rendered = json.dumps(sanitize(payload), default=str, indent=2)
        logger.info("LLM request:\n%s", rendered)
    elif mode == "pause":
        if not sys.stdin.isatty():
            raise RuntimeError("PROMPT_INSPECTION_MODE=pause requires an interactive terminal")
        # Pause mode is for inspecting the exact object passed to the SDK.
        print(json.dumps(payload, default=str, indent=2))
        if input("Send this request to OpenAI? [y/N] ").strip().lower() not in {"y", "yes"}:
            raise RuntimeError("LLM request rejected by operator")


def json_safe(value: Any) -> Any:
    """Convert SDK and Pydantic values to JSON-safe structures."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if value.__class__.__module__.startswith("unittest.mock"):
        return str(value)
    if hasattr(value, "model_dump"):
        return json_safe(value.model_dump(mode="json"))
    if hasattr(value, "to_dict"):
        return json_safe(value.to_dict())
    if hasattr(value, "dict"):
        return json_safe(value.dict())
    return str(value)


def serialized_size(value: Any) -> int:
    rendered = json.dumps(json_safe(value), default=str, separators=(",", ":"), ensure_ascii=False)
    return len(rendered.encode("utf-8"))


class InvestigationRecorder:
    """Write an ordered trace archive and optionally mirror it to Elasticsearch."""

    SCHEMA_VERSION = "1"

    def __init__(
        self,
        *,
        investigation_id: str,
        alert_id: str,
        directory: str | Path = "logs/investigations",
        elastic_client: Any | None = None,
        trace_index: str = "soc-triage-traces-v1",
        result_index: str = "soc-triage-results-v1",
        elastic_enabled: bool = True,
        experiment_id: str | None = None,
        run_number: int | None = None,
        agent_mode: str = "triage",
        logger: logging.Logger | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.alert_id = alert_id
        self.directory = Path(directory)
        self.elastic_client = elastic_client
        self.trace_index = trace_index
        self.result_index = result_index
        self.elastic_enabled = elastic_enabled
        self.experiment_id = experiment_id
        self.run_number = run_number
        self.agent_mode = agent_mode
        self.logger = logger or logging.getLogger(__name__)
        self.sequence = 0
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        self.path = self.directory / f"{investigation_id}.jsonl"

    def record(self, event_type: str, **details: Any) -> dict[str, Any]:
        self.sequence += 1
        event: dict[str, Any] = {
            "investigation_id": self.investigation_id,
            "alert_id": self.alert_id,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": self.sequence,
            "event_type": event_type,
            "schema_version": self.SCHEMA_VERSION,
            "agent_mode": self.agent_mode,
        }
        if self.experiment_id is not None:
            event["experiment_id"] = self.experiment_id
        if self.run_number is not None:
            event["run_number"] = self.run_number
        event.update(json_safe(details))

        line = json.dumps(event, default=str, separators=(",", ":"), ensure_ascii=False)
        try:
            with self.path.open("a", encoding="utf-8") as archive:
                os.chmod(self.path, 0o600)
                archive.write(line + "\n")
                archive.flush()
                os.fsync(archive.fileno())
        except OSError as exc:
            self.logger.error(
                "Failed to append investigation trace investigation_id=%s sequence=%d: %s",
                self.investigation_id,
                self.sequence,
                exc,
            )

        if self.elastic_enabled and self.elastic_client is not None:
            try:
                self.elastic_client.index_trace_event(
                    self.trace_index,
                    self.investigation_id,
                    self.sequence,
                    event,
                )
            except Exception as exc:
                self.logger.error(
                    "Elasticsearch trace persistence failed investigation_id=%s sequence=%d: %s",
                    self.investigation_id,
                    self.sequence,
                    exc,
                )
        return event

    def record_result(self, report: Any) -> None:
        document = json_safe(report.model_dump(mode="json") if hasattr(report, "model_dump") else report)
        document["@timestamp"] = datetime.now(timezone.utc).isoformat()
        if self.elastic_enabled and self.elastic_client is not None:
            try:
                self.elastic_client.index_investigation_result(
                    self.result_index,
                    self.investigation_id,
                    document,
                )
            except Exception as exc:
                self.logger.error(
                    "Elasticsearch result persistence failed investigation_id=%s: %s",
                    self.investigation_id,
                    exc,
                )

    def replay(self) -> tuple[int, int]:
        """Best-effort replay of all locally archived events to Elasticsearch."""
        if not self.elastic_enabled or self.elastic_client is None:
            return 0, 0
        indexed = 0
        failed = 0
        if not self.path.exists():
            return 0, 0
        with self.path.open("r", encoding="utf-8") as archive:
            for line in archive:
                try:
                    event = json.loads(line)
                    self.elastic_client.index_trace_event(
                        self.trace_index,
                        self.investigation_id,
                        int(event["sequence"]),
                        event,
                    )
                    indexed += 1
                except Exception as exc:
                    failed += 1
                    self.logger.error(
                        "Trace replay failed investigation_id=%s: %s",
                        self.investigation_id,
                        exc,
                    )
        return indexed, failed

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())
