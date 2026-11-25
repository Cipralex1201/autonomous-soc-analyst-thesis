"""Typed data structures shared by the Elasticsearch integration and tools."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


def strict_json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Adapt a Pydantic schema to OpenAI Structured Outputs strict mode."""
    schema = copy.deepcopy(model.model_json_schema())
    _make_strict(schema)
    return schema


def _make_strict(schema: dict[str, Any]) -> None:
    properties = schema.get("properties")
    if isinstance(properties, dict):
        schema["additionalProperties"] = False
        schema["required"] = list(properties)
        for name, property_schema in properties.items():
            if isinstance(property_schema, dict):
                _make_strict(property_schema)

    items = schema.get("items")
    if isinstance(items, dict):
        _make_strict(items)

    for variant_key in ("anyOf", "allOf", "oneOf"):
        variants = schema.get(variant_key)
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, dict):
                    _make_strict(variant)

    for definition in schema.get("$defs", {}).values():
        if isinstance(definition, dict):
            _make_strict(definition)
    schema.pop("default", None)


class AlertContext(BaseModel):
    alert_id: str
    rule_name: str | None = None
    rule_description: str | None = None
    detected_at: datetime | None = None
    severity: str | None = None
    risk_score: float | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    host_name: str | None = None
    user_name: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    detection_evidence: dict[str, Any] = Field(default_factory=dict)
    telemetry_datasets: list[str] = Field(default_factory=list)
    originating_indices: list[str] = Field(default_factory=list)
    telemetry_provenance: Literal["known", "ambiguous", "missing"] = "missing"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimeWindow(BaseModel):
    start: datetime
    end: datetime

    @field_validator("end")
    @classmethod
    def end_after_start(cls, value: datetime, info: Any) -> datetime:
        start = info.data.get("start")
        if start is not None and value <= start:
            raise ValueError("end must be after start")
        return value


class SourceActivityArgs(BaseModel):
    source_ip: str
    start: datetime
    end: datetime
    max_events: int = Field(default=100, gt=0, le=1000)


class HttpStatisticsArgs(BaseModel):
    source_ip: str
    start: datetime
    end: datetime


class RelatedAlertsArgs(BaseModel):
    source_ip: str | None = None
    host_name: str | None = None
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def require_correlating_identity(self) -> "RelatedAlertsArgs":
        if not self.source_ip and not self.host_name:
            raise ValueError("source_ip or host_name is required")
        return self


class ElasticsearchSearchArgs(BaseModel):
    index: str
    query: dict[str, Any]
    aggregations: dict[str, Any] | None = None
    source_fields: list[str] | None = None
    sort: list[dict[str, Any]] | None = None
    size: int = Field(
        default=25,
        ge=0,
        le=1000,
        description="Maximum documents to return; use 0 for aggregation-only queries.",
    )


class DiscoverFieldsArgs(BaseModel):
    index: str
    field_prefix: str | None = None
    field_pattern: str | None = None
    after_field: str | None = None
    max_fields: int = Field(default=100, gt=0, le=500)


class ToolResult(BaseModel):
    tool_name: str
    ok: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    failure_category: Literal["validation", "execution"] | None = Field(
        default=None,
        exclude=True,
    )


Assessment = Literal["true_positive", "false_positive", "uncertain"]
ProposedAction = Literal["ESCALATE", "CLOSE"]
ExecutionStatus = Literal["completed", "partial", "failed"]


class TriageAssessment(BaseModel):
    assessment: Assessment
    severity: str
    confidence: float = Field(ge=0, le=1)
    summary: str
    evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)


class TriageReport(BaseModel):
    alert_id: str
    investigation_id: str
    execution_status: ExecutionStatus
    assessment: Assessment
    proposed_action: ProposedAction
    severity: str
    confidence: float = Field(ge=0, le=1)
    summary: str
    evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    tool_call_count: int = Field(ge=0)
    model_request_count: int = Field(ge=0)
    processing_duration_seconds: float = Field(ge=0)
    provisional: bool = False
    finalization_triggered_by_budget: bool = False
    finalization_reason: str | None = None
    successful_tool_call_count: int = Field(default=0, ge=0)
    failed_tool_call_count: int = Field(default=0, ge=0)
    tool_results: list[ToolResult] = Field(default_factory=list)
    token_usage: dict[str, int] = Field(default_factory=dict)
    error: str | None = None
    model: str | None = None
    experiment_id: str | None = None
    run_number: int | None = None
    agent_mode: str | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def enforce_action_mapping(self) -> "TriageReport":
        expected = "CLOSE" if self.assessment == "false_positive" else "ESCALATE"
        if self.proposed_action != expected:
            raise ValueError("proposed_action does not match assessment policy")
        return self
