"""Bounded, read-only SIEM investigation tools."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel
from elastic_transport import ApiError, TransportError

from .config import Settings
from .elastic_client import ElasticClient
from .schemas import (
    HttpStatisticsArgs,
    RelatedAlertsArgs,
    SourceActivityArgs,
    ToolResult,
    strict_json_schema,
)


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("source_ip must be a valid IP address") from exc


def _bounded_window(start: datetime, end: datetime, settings: Settings) -> tuple[str, str]:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("time windows must include a timezone")
    duration = end - start
    if duration.total_seconds() <= 0:
        raise ValueError("end must be after start")
    if duration.total_seconds() > settings.max_query_window_minutes * 60:
        raise ValueError("time window exceeds MAX_QUERY_WINDOW_MINUTES")
    return start.astimezone(timezone.utc).isoformat(), end.astimezone(timezone.utc).isoformat()


def _time_query(start: str, end: str) -> dict[str, Any]:
    return {"range": {"@timestamp": {"gte": start, "lte": end}}}


def _total_value(total: Any) -> int:
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total or 0)


class InvestigationTools:
    def __init__(self, elastic: ElasticClient, settings: Settings) -> None:
        self.elastic = elastic
        self.settings = settings
        self.last_query: dict[str, Any] | None = None

    def _execute(self, name: str, args: BaseModel, query: dict[str, Any], size: int, index: str) -> ToolResult:
        try:
            self.last_query = {"index": index, "query": query, "size": size}
            response = self.elastic.search(index=index, query=query, size=size)
            hits = response.get("hits", {})
            return ToolResult(
                tool_name=name,
                ok=True,
                data={
                    "total": hits.get("total", 0),
                    "events": [hit.get("_source", {}) for hit in hits.get("hits", [])],
                },
            )
        except (ApiError, TransportError, ValueError, KeyError, TypeError) as exc:
            return ToolResult(tool_name=name, ok=False, error=str(exc))

    def get_source_activity(self, args: SourceActivityArgs) -> ToolResult:
        try:
            source_ip = _validate_ip(args.source_ip)
            start, end = _bounded_window(args.start, args.end, self.settings)
            query = {"bool": {"filter": [_time_query(start, end), {"term": {"source.ip": source_ip}}]}}
            return self._execute(
                "get_source_activity", args, query, min(args.max_events, self.settings.max_query_results),
                self.settings.elastic_telemetry_indices,
            )
        except ValueError as exc:
            return ToolResult(tool_name="get_source_activity", ok=False, error=str(exc))

    def get_http_statistics(self, args: HttpStatisticsArgs) -> ToolResult:
        try:
            source_ip = _validate_ip(args.source_ip)
            start, end = _bounded_window(args.start, args.end, self.settings)
            query = {"bool": {"filter": [_time_query(start, end), {"term": {"source.ip": source_ip}}]}}
            aggregations = {
                "unique_paths": {"cardinality": {"field": "url.original", "precision_threshold": 1000}},
                "status_codes": {"terms": {"field": "http.response.status_code", "size": 20}},
                "common_paths": {"terms": {"field": "url.original", "size": 20}},
                "user_agents": {"terms": {"field": "user_agent.original", "size": 20}},
                "requests_over_time": {
                    "date_histogram": {"field": "@timestamp", "fixed_interval": "1m", "min_doc_count": 0}
                },
            }
            self.last_query = {"index": self.settings.elastic_nginx_index, "query": query, "size": 0, "aggregations": aggregations}
            response = self.elastic.search(
                index=self.settings.elastic_nginx_index,
                query=query,
                size=0,
                aggregations=aggregations,
            )
            return ToolResult(
                tool_name="get_http_statistics",
                ok=True,
                data={
                    "total_requests": _total_value(response.get("hits", {}).get("total", 0)),
                    "statistics": response.get("aggregations", {}),
                },
            )
        except (ApiError, TransportError, ValueError, KeyError, TypeError) as exc:
            return ToolResult(tool_name="get_http_statistics", ok=False, error=str(exc))

    def get_related_alerts(self, args: RelatedAlertsArgs) -> ToolResult:
        try:
            start, end = _bounded_window(args.start, args.end, self.settings)
            identities = []
            if args.source_ip:
                identities.append({"term": {"source.ip": _validate_ip(args.source_ip)}})
            if args.host_name:
                identities.append({"term": {"host.name": args.host_name}})
            query = {"bool": {"filter": [_time_query(start, end)], "should": identities, "minimum_should_match": 1}}
            return self._execute(
                "get_related_alerts", args, query, self.settings.max_query_results, self.settings.elastic_alert_index,
            )
        except ValueError as exc:
            return ToolResult(tool_name="get_related_alerts", ok=False, error=str(exc))


TOOL_NAMES = ("get_source_activity", "get_http_statistics", "get_related_alerts")


def tool_definitions() -> list[dict[str, Any]]:
    """Return Responses API function definitions for the approved tools."""
    return [
        {
            "type": "function",
            "name": "get_source_activity",
            "description": "Retrieve bounded telemetry activity from an alert source IP.",
            "parameters": strict_json_schema(SourceActivityArgs),
            "strict": True,
        },
        {
            "type": "function",
            "name": "get_http_statistics",
            "description": "Calculate bounded HTTP request statistics for a source IP.",
            "parameters": strict_json_schema(HttpStatisticsArgs),
            "strict": True,
        },
        {
            "type": "function",
            "name": "get_related_alerts",
            "description": "Find related Elastic Security alerts by source IP or host.",
            "parameters": strict_json_schema(RelatedAlertsArgs),
            "strict": True,
        },
    ]
