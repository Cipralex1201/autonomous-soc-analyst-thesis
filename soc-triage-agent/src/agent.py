"""Bounded OpenAI Responses API investigation orchestration."""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Mapping
from typing import Any

from openai import OpenAI
from pydantic import ValidationError

from .config import Settings
from .observability import inspect_request, sanitize
from .prompts import alert_input, load_system_prompt
from .schemas import (
    AlertContext,
    HttpStatisticsArgs,
    RelatedAlertsArgs,
    SourceActivityArgs,
    TriageAssessment,
    TriageReport,
    ToolResult,
)
from .tools import InvestigationTools, tool_definitions


class InvestigationError(RuntimeError):
    """Raised when an investigation cannot produce a valid assessment."""


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


class TriageAgent:
    def __init__(
        self,
        settings: Settings,
        tools: InvestigationTools,
        openai_client: Any | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if openai_client is None and (not settings.openai_api_key or not settings.openai_model):
            raise ValueError("OPENAI_API_KEY and OPENAI_MODEL are required for triage")
        self.settings = settings
        self.tools = tools
        self.client = openai_client or OpenAI(api_key=settings.openai_api_key)
        self.logger = logger or logging.getLogger(__name__)
        self.prompt, self.prompt_version, self.prompt_hash = load_system_prompt()

    def run(self, alert: AlertContext) -> TriageReport:
        investigation_id = str(uuid.uuid4())
        started = time.monotonic()
        requests = 0
        tool_calls = 0
        try:
            response = None
            input_items: Any = alert_input(alert)
            while requests < self.settings.max_model_requests:
                payload: dict[str, Any] = {
                    "model": self.settings.openai_model,
                    "instructions": self.prompt,
                    "input": input_items,
                    "tools": tool_definitions(),
                    "text": {
                        "format": {
                            "type": "json_schema",
                            "name": "triage_assessment",
                            "schema": TriageAssessment.model_json_schema(),
                            "strict": True,
                        }
                    },
                }
                if self.settings.prompt_inspection_mode == "pause" or (
                    self.settings.prompt_inspection_mode == "log" and self.settings.log_llm_requests
                ):
                    inspect_request(payload, self.settings.prompt_inspection_mode, self.logger)
                requests += 1
                response = self.client.responses.create(**payload)
                output = list(_value(response, "output", []) or [])
                if self.settings.log_llm_responses:
                    self.logger.info("LLM response investigation_id=%s: %s", investigation_id, sanitize(output))
                calls = [item for item in output if _value(item, "type") == "function_call"]
                if not calls:
                    assessment = self._parse_assessment(response)
                    return self._report(alert, investigation_id, assessment, requests, tool_calls, started)
                if tool_calls + len(calls) > self.settings.max_tool_calls:
                    raise InvestigationError("maximum SIEM tool-call budget exhausted")
                follow_up: list[Any] = [self._serializable(item) for item in output]
                for call in calls:
                    result = self._execute_call(call, investigation_id)
                    tool_calls += 1
                    follow_up.append(
                        {
                            "type": "function_call_output",
                            "call_id": _value(call, "call_id"),
                            "output": result.model_dump_json(),
                        }
                    )
                input_items = follow_up
            raise InvestigationError("maximum model-request budget exhausted")
        except Exception as exc:
            self.logger.error("Investigation failed investigation_id=%s: %s", investigation_id, exc)
            return self._failure_report(
                alert, investigation_id, str(exc), requests, tool_calls, started
            )

    def _execute_call(self, call: Any, investigation_id: str) -> ToolResult:
        name = _value(call, "name", "")
        raw_arguments = _value(call, "arguments", "{}")
        if self.settings.log_tool_calls:
            self.logger.info(
                "Tool call investigation_id=%s name=%s requested_arguments=%s",
                investigation_id,
                name,
                sanitize(raw_arguments),
            )
        models = {
            "get_source_activity": (SourceActivityArgs, self.tools.get_source_activity),
            "get_http_statistics": (HttpStatisticsArgs, self.tools.get_http_statistics),
            "get_related_alerts": (RelatedAlertsArgs, self.tools.get_related_alerts),
        }
        if name not in models:
            result = ToolResult(tool_name=name or "unknown", ok=False, error="unknown tool")
        else:
            model, function = models[name]
            try:
                arguments = model.model_validate_json(raw_arguments)
                result = function(arguments)
                if self.settings.log_tool_calls:
                    self.logger.info(
                        "Tool validated arguments investigation_id=%s name=%s arguments=%s query=%s",
                        investigation_id,
                        name,
                        sanitize(arguments.model_dump()),
                        sanitize(self.tools.last_query),
                    )
            except (ValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
                result = ToolResult(tool_name=name, ok=False, error=f"invalid tool arguments: {exc}")
        if self.settings.log_tool_results:
            self.logger.info("Tool result investigation_id=%s name=%s result=%s", investigation_id, name, sanitize(result.model_dump()))
        return result

    @staticmethod
    def _serializable(item: Any) -> Any:
        if hasattr(item, "model_dump"):
            return item.model_dump()
        return item

    @staticmethod
    def _parse_assessment(response: Any) -> TriageAssessment:
        text = _value(response, "output_text")
        if not text:
            raise InvestigationError("model returned no structured assessment")
        try:
            return TriageAssessment.model_validate_json(text)
        except (ValidationError, ValueError, TypeError) as exc:
            raise InvestigationError(f"malformed structured assessment: {exc}") from exc

    def _report(
        self,
        alert: AlertContext,
        investigation_id: str,
        assessment: TriageAssessment,
        requests: int,
        tool_calls: int,
        started: float,
    ) -> TriageReport:
        report = TriageReport(
            alert_id=alert.alert_id,
            investigation_id=investigation_id,
            assessment=assessment.assessment,
            proposed_action="CLOSE" if assessment.assessment == "false_positive" else "ESCALATE",
            severity=assessment.severity,
            confidence=assessment.confidence,
            summary=assessment.summary,
            evidence=assessment.evidence,
            missing_evidence=assessment.missing_evidence,
            recommended_next_steps=assessment.recommended_next_steps,
            tool_call_count=tool_calls,
            model_request_count=requests,
            processing_duration_seconds=time.monotonic() - started,
        )
        if self.settings.log_triage_results:
            self.logger.info("Triage result investigation_id=%s: %s", investigation_id, report.model_dump())
        return report

    def _failure_report(
        self,
        alert: AlertContext,
        investigation_id: str,
        error: str,
        requests: int,
        tool_calls: int,
        started: float,
    ) -> TriageReport:
        return TriageReport(
            alert_id=alert.alert_id,
            investigation_id=investigation_id,
            assessment="uncertain",
            proposed_action="ESCALATE",
            severity=alert.severity or "unknown",
            confidence=0,
            summary="Investigation did not produce a safe triage decision.",
            missing_evidence=[error],
            recommended_next_steps=["Review the alert manually."],
            tool_call_count=tool_calls,
            model_request_count=requests,
            processing_duration_seconds=time.monotonic() - started,
        )
