"""Bounded OpenAI Responses API investigation orchestration."""

from __future__ import annotations

import json
import logging
import subprocess
import time
from collections.abc import Mapping
from typing import Any

from openai import OpenAI
from pydantic import ValidationError

from .config import Settings, configured_index_patterns
from .observability import InvestigationRecorder, inspect_request, json_safe, sanitize, serialized_size
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
        self._git_commit = self._detect_git_commit()

    @staticmethod
    def _detect_git_commit() -> str | None:
        try:
            return subprocess.run(
                ["git", "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            ).stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            return None

    def _configuration_snapshot(self) -> dict[str, Any]:
        return {
            "model": self.settings.openai_model,
            "prompt_version": self.prompt_version,
            "prompt_hash": self.prompt_hash,
            "agent_version": "1",
            "git_commit": self._git_commit,
            "max_model_requests": self.settings.max_model_requests,
            "max_tool_calls": self.settings.max_tool_calls,
            "max_query_results": self.settings.max_query_results,
            "max_query_window_minutes": self.settings.max_query_window_minutes,
            "max_tool_result_bytes": self.settings.max_tool_result_bytes,
            "elastic_search_timeout_seconds": self.settings.elastic_search_timeout_seconds,
            "agent_mode": self.settings.agent_mode,
            "experiment_id": self.settings.experiment_id,
            "run_number": self.settings.run_number,
        }

    def run(self, alert: AlertContext) -> TriageReport:
        investigation_id = InvestigationRecorder.new_id()
        started = time.monotonic()
        requests = 0
        tool_calls = 0
        successful_tool_calls = 0
        failed_tool_calls = 0
        tool_results: list[ToolResult] = []
        token_usage: dict[str, int] = {}
        finalization_reason: str | None = None
        elastic = getattr(self.tools, "elastic", None)
        recorder: InvestigationRecorder | None = None
        if self.settings.investigation_tracing_enabled:
            recorder = InvestigationRecorder(
                investigation_id=investigation_id,
                alert_id=alert.alert_id,
                directory=self.settings.investigation_trace_directory,
                elastic_client=elastic if self.settings.investigation_trace_elastic_enabled else None,
                trace_index=self.settings.elastic_triage_traces_index,
                result_index=self.settings.elastic_triage_results_index,
                elastic_enabled=self.settings.investigation_trace_elastic_enabled,
                experiment_id=self.settings.experiment_id,
                run_number=self.settings.run_number,
                agent_mode=self.settings.agent_mode,
                logger=self.logger,
            )
            if elastic is not None and self.settings.investigation_trace_elastic_enabled:
                try:
                    elastic.ensure_trace_mappings()
                except Exception as exc:
                    self.logger.error("Elasticsearch trace mapping setup failed: %s", exc)
            recorder.record(
                "investigation.started",
                model=self.settings.openai_model,
                agent_mode=self.settings.agent_mode,
                configuration=self._configuration_snapshot(),
                prompt={"version": self.prompt_version, "hash": self.prompt_hash},
            )
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
                if recorder is not None:
                    recorder.record(
                        "llm.request",
                        model_request_number=requests,
                        previous_response_id=payload.get("previous_response_id"),
                        llm={
                            "parameters": payload,
                            "request_bytes": serialized_size(payload),
                        },
                    )
                request_started = time.monotonic()
                response = self.client.responses.create(**payload)
                request_latency = time.monotonic() - request_started
                self._record_usage(response, token_usage)
                output = list(_value(response, "output", []) or [])
                if recorder is not None:
                    recorder.record(
                        "llm.response",
                        model_request_number=requests,
                        response_id=self._response_id(response),
                        status=_value(response, "status"),
                        llm={
                            "output": output,
                            "response": response,
                            "usage": self._usage_payload(response),
                        },
                        metrics={
                            "llm_request_latency_seconds": request_latency,
                            "serialized_response_bytes": serialized_size({"output": output}),
                        },
                    )
                if self.settings.log_llm_responses:
                    self.logger.info(
                        "LLM response investigation_id=%s: %s",
                        investigation_id,
                        self._response_summary(output),
                    )
                calls = [item for item in output if _value(item, "type") == "function_call"]
                if not calls:
                    assessment = self._parse_assessment(response)
                    report = self._report(
                        alert, investigation_id, assessment, requests, tool_calls,
                        successful_tool_calls, failed_tool_calls, tool_results,
                        token_usage, started,
                    )
                    if recorder is not None:
                        recorder.record(
                            "investigation.completed",
                            status="completed",
                            provisional=False,
                            final={"verdict": report.model_dump(mode="json"), "configuration": self._configuration_snapshot()},
                            metrics={"investigation_duration_seconds": report.processing_duration_seconds},
                        )
                        recorder.record_result(report)
                    return report
                if tool_calls + len(calls) > self.settings.max_tool_calls:
                    finalization_reason = "SIEM tool-call budget exhausted"
                    break
                follow_up: list[Any] = []
                for call in calls:
                    result = self._execute_call(call, investigation_id, recorder)
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
            if recorder is not None:
                recorder.record(
                    "llm.request",
                    model_request_number=requests,
                    previous_response_id=final_payload.get("previous_response_id"),
                    llm={
                        "parameters": final_payload,
                        "request_bytes": serialized_size(final_payload),
                    },
                )
            request_started = time.monotonic()
            final_response = self.client.responses.create(**final_payload)
            request_latency = time.monotonic() - request_started
            self._record_usage(final_response, token_usage)
            if recorder is not None:
                final_output = list(_value(final_response, "output", []) or [])
                recorder.record(
                    "llm.response",
                    model_request_number=requests,
                    response_id=self._response_id(final_response),
                    status=_value(final_response, "status"),
                    llm={
                        "output": final_output,
                        "response": final_response,
                        "usage": self._usage_payload(final_response),
                    },
                    metrics={
                        "llm_request_latency_seconds": request_latency,
                        "serialized_response_bytes": serialized_size({"output": final_output}),
                    },
                )
            assessment = self._parse_assessment(final_response)
            report = self._report(
                alert, investigation_id, assessment, requests, tool_calls,
                successful_tool_calls, failed_tool_calls, tool_results,
                token_usage, started, execution_status="partial",
                finalization_reason=finalization_reason,
            )
            if recorder is not None:
                recorder.record(
                    "investigation.completed",
                    status="partial",
                    provisional=True,
                    final={"verdict": report.model_dump(mode="json"), "configuration": self._configuration_snapshot()},
                    metrics={"investigation_duration_seconds": report.processing_duration_seconds},
                )
                recorder.record_result(report)
            return report
        except Exception as exc:
            self.logger.error("Investigation failed investigation_id=%s: %s", investigation_id, exc)
            report = self._failure_report(
                alert, investigation_id, str(exc), requests, tool_calls,
                successful_tool_calls, failed_tool_calls, tool_results,
                token_usage, started, finalization_reason,
            )
            if recorder is not None:
                recorder.record(
                    "investigation.failed",
                    status="failed",
                    provisional=False,
                    error={"technical_failure": str(exc), "stage": "investigation"},
                    evidence=[result.model_dump(mode="json") for result in tool_results],
                    metrics={
                        "investigation_duration_seconds": report.processing_duration_seconds,
                        "model_request_count": requests,
                        "tool_call_count": tool_calls,
                        "successful_tool_call_count": successful_tool_calls,
                        "failed_tool_call_count": failed_tool_calls,
                        "token_usage": token_usage,
                    },
                    final={"configuration": self._configuration_snapshot()},
                )
                recorder.record_result(report)
            return report

    def _execute_call(
        self,
        call: Any,
        investigation_id: str,
        recorder: InvestigationRecorder | None = None,
    ) -> ToolResult:
        name = _value(call, "name", "")
        raw_arguments = _value(call, "arguments", "{}")
        call_id = _value(call, "call_id")
        tool_started = time.monotonic()
        if recorder is not None:
            recorder.record(
                "tool.called",
                call_id=call_id,
                tool={"name": name or "unknown", "requested_arguments": raw_arguments},
            )
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
                duration = time.monotonic() - tool_started
                if recorder is not None:
                    if result.ok:
                        recorder.record(
                            "tool.completed",
                            call_id=call_id,
                            tool={
                                "name": name,
                                "validated_arguments": arguments.model_dump(mode="json"),
                                "executed_elasticsearch_dsl": getattr(self.tools, "last_query", None),
                                "result": result.data,
                                "status": "completed",
                                "result_bytes": serialized_size(result.data),
                                "truncated": bool(result.data.get("truncated")),
                            },
                            metrics={"tool_execution_seconds": duration},
                            duration_seconds=duration,
                        )
                    else:
                        recorder.record(
                            "tool.failed",
                            call_id=call_id,
                            tool={"name": name, "requested_arguments": raw_arguments},
                            error={"stage": "execution", "message": result.error},
                            metrics={"tool_execution_seconds": duration},
                            duration_seconds=duration,
                        )
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
                duration = time.monotonic() - tool_started
                if recorder is not None:
                    recorder.record(
                        "tool.failed",
                        call_id=call_id,
                        tool={"name": name, "requested_arguments": raw_arguments},
                        error={"stage": "validation", "message": str(exc)},
                        metrics={"tool_execution_seconds": duration},
                        duration_seconds=duration,
                    )
        if name not in models and recorder is not None:
            duration = time.monotonic() - tool_started
            recorder.record(
                "tool.failed",
                call_id=call_id,
                tool={"name": name or "unknown", "requested_arguments": raw_arguments},
                error={"stage": "validation", "message": "unknown tool"},
                metrics={"tool_execution_seconds": duration},
                duration_seconds=duration,
            )
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
        input_details = _value(usage, "input_tokens_details", {})
        cached = _value(input_details, "cached_tokens")
        if isinstance(cached, int):
            token_usage["cached_input_tokens"] = token_usage.get("cached_input_tokens", 0) + cached
        output_details = _value(usage, "output_tokens_details", {})
        reasoning = _value(output_details, "reasoning_tokens")
        if isinstance(reasoning, int):
            token_usage["reasoning_output_tokens"] = token_usage.get("reasoning_output_tokens", 0) + reasoning

    def _usage_payload(self, response: Any) -> dict[str, Any]:
        usage = _value(response, "usage", {})
        if usage is None:
            return {}
        if isinstance(usage, Mapping):
            return dict(usage)
        return json_safe(usage)

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
            model=self.settings.openai_model,
            experiment_id=self.settings.experiment_id,
            run_number=self.settings.run_number,
            agent_mode=self.settings.agent_mode,
            configuration=self._configuration_snapshot(),
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
            model=self.settings.openai_model,
            experiment_id=self.settings.experiment_id,
            run_number=self.settings.run_number,
            agent_mode=self.settings.agent_mode,
            configuration=self._configuration_snapshot(),
        )
