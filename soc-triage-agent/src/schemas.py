"""Typed data structures shared by the Elasticsearch integration and tools."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


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


class ToolResult(BaseModel):
    tool_name: str
    ok: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


Assessment = Literal["true_positive", "false_positive", "uncertain"]
ProposedAction = Literal["ESCALATE", "CLOSE"]
