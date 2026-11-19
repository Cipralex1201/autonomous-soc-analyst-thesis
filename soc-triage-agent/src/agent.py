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

from .config import Settings, configured_index_patterns
from .observability import inspect_request, sanitize
from .prompts import alert_input, finalization_input, load_system_prompt
from .schemas import (
    AlertContext,
    DiscoverFieldsArgs,
    ElasticsearchSearchArgs,
    TriageAssessment,
    TriageReport,
    ToolResult,
    strict_json_schema,
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
        successful_tool_calls = 0
        failed_tool_calls = 0
        tool_results: list[ToolResult] = []
        token_usage: dict[str, int] = {}
        finalization_reason: str | None = None
        try:
            input_items: Any = alert_input(
                alert,
                self.settings.max_query_window_minutes,
                configured_index_patterns(self.settings),
            )
            previous_response_id: str | None = None
            while requests < self.settings.max_model_requests:
                # The last configured request is reserved for a no-tools assessment.
                if requests == self.settings.max_model_requests - 1:
                    finalization_reason = "model-request budget nearly exhausted"
                    break
                payload: dict[str, Any] = {
                    "model": self.settings.openai_model,
                    "instructions": (
                        f"{self.prompt}\n\nInvestigation budget: "
                        f"{self.settings.max_model_requests - requests - 1} model requests "
                        f"remain for investigation after this request and "
                        f"{self.settings.max_tool_calls - tool_calls} SIEM tool calls remain. "
                        "Prioritize unresolved questions, avoid redundant queries, and "
                        "finalize early when the evidence is sufficient."
                    ),
                    "input": input_items,
                    "tools": tool_definitions(),
                    "text": {
                        "format": {
                            "type": "json_schema",
                            "name": "triage_assessment",
                            "schema": strict_json_schema(TriageAssessment),
                            "strict": True,
                        }
                    },
                }
                if previous_response_id is not None:
                    payload["previous_response_id"] = previous_response_id
                if self.settings.prompt_inspection_mode == "pause" or (
                    self.settings.prompt_inspection_mode == "log" and self.settings.log_llm_requests
                ):
                    inspect_request(payload, self.settings.prompt_inspection_mode, self.logger)
                requests += 1
                response = self.client.responses.create(**payload)
                self._record_usage(response, token_usage)
                output = list(_value(response, "output", []) or [])
                if self.settings.log_llm_responses:
                    self.logger.info(
                        "LLM response investigation_id=%s: %s",
                        investigation_id,
                        self._response_summary(output),
                    )
                calls = [item for item in output if _value(item, "type") == "function_call"]
                if not calls:
                    assessment = self._parse_assessment(response)
                    return self._report(
                        alert, investigation_id, assessment, requests, tool_calls,
                        successful_tool_calls, failed_tool_calls, tool_results,
                        token_usage, started,
                    )
                if tool_calls + len(calls) > self.settings.max_tool_calls:
                    finalization_reason = "SIEM tool-call budget exhausted"
                    break
                follow_up: list[Any] = []
                for call in calls:
                    result = self._execute_call(call, investigation_id)
                    tool_calls += 1
                    tool_results.append(result)
                    if result.ok:
                        successful_tool_calls += 1
                    else:
                        failed_tool_calls += 1
                    follow_up.append(
                        {
                            "type": "function_call_output",
                            "call_id": _value(call, "call_id"),
                            "output": result.model_dump_json(),
                        }
                    )
                previous_response_id = self._response_id(response)
                input_items = (
                    follow_up
                    if previous_response_id is not None
                    else [self._function_call_input(call) for call in calls] + follow_up
                )
            if finalization_reason is None:
                finalization_reason = "investigation budget exhausted"
            if requests >= self.settings.max_model_requests:
                raise InvestigationError("no model request remained for finalization")

            self.logger.info(
                "Finalizing investigation_id=%s reason=%s model_requests=%d tool_calls=%d "
                "successful_tool_calls=%d failed_tool_calls=%d",
                investigation_id,
                finalization_reason,
                requests,
                tool_calls,
                successful_tool_calls,
                failed_tool_calls,
            )
            final_payload: dict[str, Any] = {
                "model": self.settings.openai_model,
                "instructions": self.prompt,
                "input": finalization_input(
                    reason=finalization_reason,
                    collected_results=[result.model_dump() for result in tool_results],
                    remaining_model_requests=self.settings.max_model_requests - requests,
                    remaining_tool_calls=self.settings.max_tool_calls - tool_calls,
                ),
                "tools": [],
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "triage_assessment",
                        "schema": strict_json_schema(TriageAssessment),
                        "strict": True,
                    }
                },
            }
            if previous_response_id is not None:
                final_payload["previous_response_id"] = previous_response_id
            else:
                final_payload["input"] = (
                    input_items + [final_payload["input"]]
                    if isinstance(input_items, list)
                    else [input_items, final_payload["input"]]
                )
            if self.settings.prompt_inspection_mode == "pause" or (
                self.settings.prompt_inspection_mode == "log" and self.settings.log_llm_requests
            ):
                inspect_request(final_payload, self.settings.prompt_inspection_mode, self.logger)
            requests += 1
            final_response = self.client.responses.create(**final_payload)
            self._record_usage(final_response, token_usage)
            assessment = self._parse_assessment(final_response)
            return self._report(
                alert, investigation_id, assessment, requests, tool_calls,
                successful_tool_calls, failed_tool_calls, tool_results,
                token_usage, started, execution_status="partial",
                finalization_reason=finalization_reason,
            )
        except Exception as exc:
            self.logger.error("Investigation failed investigation_id=%s: %s", investigation_id, exc)
            return self._failure_report(
                alert, investigation_id, str(exc), requests, tool_calls,
                successful_tool_calls, failed_tool_calls, tool_results,
                token_usage, started, finalization_reason,
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
            "search_elasticsearch": (ElasticsearchSearchArgs, self.tools.search_elasticsearch),
            "discover_fields": (DiscoverFieldsArgs, self.tools.discover_fields),
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
    def _response_id(response: Any) -> str | None:
        response_id = _value(response, "id")
        return response_id if isinstance(response_id, str) and response_id else None

    @staticmethod
    def _record_usage(response: Any, token_usage: dict[str, int]) -> None:
        usage = _value(response, "usage", {})
        if usage is None:
            return
        for key in ("input_tokens", "output_tokens", "total_tokens"):
            value = _value(usage, key)
            if isinstance(value, int):
                token_usage[key] = token_usage.get(key, 0) + value

    @staticmethod
    def _function_call_input(call: Any) -> dict[str, Any]:
        return {
            "type": "function_call",
            "call_id": _value(call, "call_id"),
            "name": _value(call, "name"),
            "arguments": _value(call, "arguments", "{}"),
        }

    @staticmethod
    def _response_summary(output: list[Any]) -> dict[str, Any]:
        items = []
        for item in output:
            item_type = _value(item, "type", "unknown")
            summary: dict[str, Any] = {"type": item_type}
            if item_type == "function_call":
                summary.update(
                    {
                        "name": _value(item, "name"),
                        "call_id": _value(item, "call_id"),
                    }
                )
            items.append(summary)
        return {"item_count": len(output), "items": items}

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
        successful_tool_calls: int,
        failed_tool_calls: int,
        tool_results: list[ToolResult],
        token_usage: dict[str, int],
        started: float,
        execution_status: str = "completed",
        finalization_reason: str | None = None,
    ) -> TriageReport:
        report = TriageReport(
            alert_id=alert.alert_id,
            investigation_id=investigation_id,
            execution_status=execution_status,
            assessment=assessment.assessment,
            proposed_action="CLOSE" if assessment.assessment == "false_positive" else "ESCALATE",
            severity=assessment.severity,
            confidence=assessment.confidence,
            summary=assessment.summary,
            evidence=assessment.evidence,
            missing_evidence=assessment.missing_evidence,
            recommended_next_steps=(
                assessment.recommended_next_steps
                + (["Human review is required before implementing any closure decision."]
                   if execution_status == "partial" else [])
            ),
            tool_call_count=tool_calls,
            model_request_count=requests,
            processing_duration_seconds=time.monotonic() - started,
            provisional=execution_status == "partial",
            finalization_triggered_by_budget=execution_status == "partial",
            finalization_reason=finalization_reason,
            successful_tool_call_count=successful_tool_calls,
            failed_tool_call_count=failed_tool_calls,
            tool_results=tool_results,
            token_usage=token_usage,
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
        successful_tool_calls: int,
        failed_tool_calls: int,
        tool_results: list[ToolResult],
        token_usage: dict[str, int],
        started: float,
        finalization_reason: str | None = None,
    ) -> TriageReport:
        return TriageReport(
            alert_id=alert.alert_id,
            investigation_id=investigation_id,
            execution_status="failed",
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
            provisional=False,
            finalization_triggered_by_budget=finalization_reason is not None,
            finalization_reason=finalization_reason,
            successful_tool_call_count=successful_tool_calls,
            failed_tool_call_count=failed_tool_calls,
            tool_results=tool_results,
            token_usage=token_usage,
            error=error,
        )
