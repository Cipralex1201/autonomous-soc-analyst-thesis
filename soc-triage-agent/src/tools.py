"""Bounded, read-only SIEM investigation tools."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from collections.abc import Callable, Mapping
from typing import Any

from pydantic import BaseModel
from elastic_transport import ApiError, TransportError

from .config import Settings
from .elastic_client import ElasticClient
from .evidence import compact_alert, compact_event
from .schemas import (
    HttpStatisticsArgs,
    DiscoverFieldsArgs,
    ElasticsearchSearchArgs,
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


_EVENT_SOURCE_FIELDS = [
    "@timestamp",
    "event.*",
    "source.*",
    "destination.*",
    "host.name",
    "user.name",
    "http.*",
    "url.*",
    "user_agent.original",
    "process.*",
    "file.*",
    "dns.*",
    "network.*",
    "authentication.*",
    "Esql.*",
    "detection.*",
    "threat.*",
]
_ALERT_SOURCE_FIELDS = [
    "@timestamp",
    "kibana.alert.rule.name",
    "kibana.alert.rule.rule_name",
    "kibana.alert.severity",
    "kibana.alert.risk_score",
    "kibana.alert.original_time",
    "source.*",
    "destination.*",
    "host.name",
    "user.name",
    "event.*",
    "authentication.*",
    "Esql.*",
    "detection.*",
    "threat.*",
]
_UNSAFE_QUERY_KEYS = {
    "collapse",
    "knn",
    "pit",
    "runtime_mappings",
    "script",
    "script_fields",
    "scroll",
    "search_after",
}
_MAX_QUERY_NODES = 250
_MAX_QUERY_DEPTH = 10
_MAX_SOURCE_FIELDS = 50
_MAX_SORT_FIELDS = 5
_MAX_AGGREGATION_BUCKETS = 100
_BLOCKED_SOURCE_PREFIXES = (
    "agent.",
    "ecs.",
    "kibana.alert.rule.parameters",
    "log.",
    "observer.",
    "os.",
)


def _configured_index(settings: Settings, index: str) -> bool:
    return index in {
        settings.elastic_telemetry_indices,
        settings.elastic_nginx_index,
        settings.elastic_alert_index,
    }


def _validate_query_structure(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > _MAX_QUERY_NODES or depth > _MAX_QUERY_DEPTH:
        raise ValueError("query structure exceeds safety limits")
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if key_text.lower() in _UNSAFE_QUERY_KEYS:
                raise ValueError(f"query feature is not permitted: {key_text}")
            _validate_query_structure(child, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for child in value:
            _validate_query_structure(child, depth=depth + 1, nodes=nodes)
    elif isinstance(value, str) and len(value) > 4000:
        raise ValueError("query string exceeds safety limits")


def _validate_search_args(args: ElasticsearchSearchArgs, settings: Settings) -> None:
    if not _configured_index(settings, args.index):
        raise ValueError("index is not configured for this application")
    _validate_query_structure(args.query)
    if args.aggregations is not None:
        _validate_query_structure(args.aggregations)
        _validate_aggregation_limits(args.aggregations)
    if args.source_fields is not None:
        if len(args.source_fields) > _MAX_SOURCE_FIELDS:
            raise ValueError("source_fields exceeds safety limits")
        for field_name in args.source_fields:
            if not field_name.strip() or len(field_name) > 200:
                raise ValueError("source field name is invalid")
            if field_name == "*" or field_name.startswith(_BLOCKED_SOURCE_PREFIXES):
                raise ValueError(f"source field is not permitted: {field_name}")
    if args.sort is not None:
        if len(args.sort) > _MAX_SORT_FIELDS:
            raise ValueError("sort exceeds safety limits")
        for sort_field in args.sort:
            if len(sort_field) != 1:
                raise ValueError("each sort entry must contain one field")
            field_name, direction = next(iter(sort_field.items()))
            if field_name in {"_id", "_source"}:
                raise ValueError("sorting by _id or _source is not permitted; use _shard_doc")
            if isinstance(direction, Mapping):
                direction = direction.get("order")
            if direction not in {"asc", "desc"}:
                raise ValueError("sort direction must be asc or desc")


def _validate_aggregation_limits(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in {"size", "shard_size"}:
                if not isinstance(child, int) or child <= 0:
                    raise ValueError("aggregation bucket size must be positive")
                if child > _MAX_AGGREGATION_BUCKETS:
                    raise ValueError("aggregation bucket size exceeds safety limits")
            _validate_aggregation_limits(child)
    elif isinstance(value, list):
        for child in value:
            _validate_aggregation_limits(child)


def _compact_generic_aggregations(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_QUERY_DEPTH:
        return {"omitted": True, "reason": "aggregation depth limit"}
    if isinstance(value, list):
        if len(value) > _MAX_AGGREGATION_BUCKETS:
            return {
                "values": [_compact_generic_aggregations(item, depth=depth + 1)
                           for item in value[:_MAX_AGGREGATION_BUCKETS]],
                "omitted_count": len(value) - _MAX_AGGREGATION_BUCKETS,
            }
        return [_compact_generic_aggregations(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            output_key = "count" if key == "doc_count" else key
            result[str(output_key)] = _compact_generic_aggregations(child, depth=depth + 1)
        if "sum_other_doc_count" in value:
            result["omitted_count"] = value["sum_other_doc_count"]
            result.pop("sum_other_doc_count", None)
        return result
    return value


def _compact_search_result(
    response: Mapping[str, Any],
    *,
    source_fields: list[str],
    size: int,
    max_bytes: int,
) -> dict[str, Any]:
    hits = response.get("hits", {})
    if not isinstance(hits, Mapping):
        hits = {}
    total = _total_value(hits.get("total", 0))
    raw_hits = hits.get("hits", [])
    if not isinstance(raw_hits, list):
        raw_hits = []
    compact_hits = [
        {
            "id": str(hit.get("_id", "")),
            "evidence": compact_event(hit.get("_source", {}), source_fields),
        }
        for hit in raw_hits
        if isinstance(hit, Mapping) and isinstance(hit.get("_source", {}), Mapping)
    ]
    result: dict[str, Any] = {
        "total_hits": total,
        "returned_hits": len(compact_hits),
        "sampled": total > len(compact_hits),
        "truncated": False,
        "hits": compact_hits,
        "aggregations": _compact_generic_aggregations(response.get("aggregations", {})),
        "source_fields": source_fields,
        "omitted_fields": [
            "unrequested source fields",
            "agent.*",
            "ecs.*",
            "input.*",
            "log.*",
            "observer.*",
            "os.*",
        ],
    }
    if len(json.dumps(result, default=str, separators=(",", ":"))) <= max_bytes:
        return result

    result["truncated"] = True
    result["truncation_reason"] = "compact result exceeded MAX_TOOL_RESULT_BYTES"
    result["omitted_hit_count"] = len(compact_hits)
    result["hits"] = []
    if len(json.dumps(result, default=str, separators=(",", ":"))) <= max_bytes:
        return result

    result["aggregations"] = {}
    result["omitted_aggregation_data"] = True
    if len(json.dumps(result, default=str, separators=(",", ":"))) <= max_bytes:
        return result

    return {
        "total_hits": total,
        "returned_hits": 0,
        "sampled": total > 0,
        "truncated": True,
        "truncation_reason": "compact result exceeded MAX_TOOL_RESULT_BYTES",
        "omitted_hit_count": len(compact_hits),
        "omitted_aggregation_data": True,
    }


def _compact_buckets(
    aggregations: Mapping[str, Any],
    name: str,
    value_name: str,
) -> dict[str, Any]:
    aggregation = aggregations.get(name, {})
    if not isinstance(aggregation, Mapping):
        return {"values": []}
    values = []
    for bucket in aggregation.get("buckets", []):
        if not isinstance(bucket, Mapping):
            continue
        value = bucket.get("key_as_string", bucket.get("key"))
        values.append({value_name: value, "count": bucket.get("doc_count", 0)})
    result: dict[str, Any] = {"values": values}
    omitted = aggregation.get("sum_other_doc_count")
    if omitted:
        result["omitted_count"] = omitted
    return result


def _compact_http_statistics(response: Mapping[str, Any]) -> dict[str, Any]:
    aggregations = response.get("aggregations", {})
    if not isinstance(aggregations, Mapping):
        aggregations = {}
    unique_paths = aggregations.get("unique_paths", {})
    unique_url_count = unique_paths.get("value", 0) if isinstance(unique_paths, Mapping) else 0
    return {
        "total_requests": _total_value(response.get("hits", {}).get("total", 0)),
        "unique_url_count": unique_url_count,
        "status_counts": _compact_buckets(aggregations, "status_codes", "status_code"),
        "noteworthy_paths": _compact_buckets(aggregations, "common_paths", "path"),
        "user_agent_counts": _compact_buckets(aggregations, "user_agents", "user_agent"),
        "requests_over_time": _compact_buckets(
            aggregations, "requests_over_time", "timestamp"
        ),
        "aggregation_note": (
            "Path, status, and user-agent values are top aggregation buckets; "
            "omitted counts are reported where Elasticsearch provides them. "
            "Raw Elasticsearch aggregation metadata is omitted."
        ),
        "omitted_fields": ["raw aggregation metadata", "unbucketed document fields"],
    }


class InvestigationTools:
    def __init__(self, elastic: ElasticClient, settings: Settings) -> None:
        self.elastic = elastic
        self.settings = settings
        self.last_query: dict[str, Any] | None = None

    def search_elasticsearch(self, args: ElasticsearchSearchArgs) -> ToolResult:
        try:
            _validate_search_args(args, self.settings)
            size = min(args.size, self.settings.max_query_results)
            source_fields = args.source_fields or _EVENT_SOURCE_FIELDS
            sort = args.sort or [{"@timestamp": "asc"}, {"_shard_doc": "asc"}]
            response = self.elastic.search(
                index=args.index,
                query=args.query,
                size=size,
                aggregations=args.aggregations,
                source=source_fields,
                sort=sort,
                timeout=f"{self.settings.elastic_search_timeout_seconds}s",
            )
            return ToolResult(
                tool_name="search_elasticsearch",
                ok=True,
                data=_compact_search_result(
                    response,
                    source_fields=source_fields,
                    size=size,
                    max_bytes=self.settings.max_tool_result_bytes,
                ),
            )
        except (ApiError, TransportError, ValueError, KeyError, TypeError) as exc:
            return ToolResult(tool_name="search_elasticsearch", ok=False, error=str(exc))

    def discover_fields(self, args: DiscoverFieldsArgs) -> ToolResult:
        try:
            if not _configured_index(self.settings, args.index):
                raise ValueError("index is not configured for this application")
            if args.field_prefix and len(args.field_prefix) > 200:
                raise ValueError("field_prefix exceeds safety limits")
            pattern = f"{args.field_prefix}*" if args.field_prefix else "*"
            response = self.elastic.field_caps(
                index=args.index,
                fields=[pattern],
                timeout=f"{self.settings.elastic_search_timeout_seconds}s",
            )
            raw_fields = response.get("fields", {})
            if not isinstance(raw_fields, Mapping):
                raise ValueError("Elasticsearch returned invalid field capabilities")
            names = sorted(
                name for name in raw_fields
                if not args.field_prefix or name.startswith(args.field_prefix)
            )
            fields = []
            for name in names[:args.max_fields]:
                definitions = raw_fields.get(name, {})
                types = []
                if isinstance(definitions, Mapping):
                    for type_name, metadata in sorted(definitions.items()):
                        entry = {"type": type_name}
                        if isinstance(metadata, Mapping):
                            entry["searchable"] = bool(metadata.get("searchable", False))
                            entry["aggregatable"] = bool(metadata.get("aggregatable", False))
                        types.append(entry)
                fields.append({"field": name, "types": types})
            return ToolResult(
                tool_name="discover_fields",
                ok=True,
                data={
                    "field_count": len(names),
                    "returned_fields": len(fields),
                    "truncated": len(names) > len(fields),
                    "fields": fields,
                    "omitted_field_count": max(0, len(names) - len(fields)),
                },
            )
        except (ApiError, TransportError, ValueError, KeyError, TypeError) as exc:
            return ToolResult(tool_name="discover_fields", ok=False, error=str(exc))

    def _execute(
        self,
        name: str,
        args: BaseModel,
        query: dict[str, Any],
        size: int,
        index: str,
        *,
        normalizer: Callable[[Mapping[str, Any]], dict[str, Any]],
        source: list[str],
        sort: list[Mapping[str, Any] | str] | None = None,
    ) -> ToolResult:
        try:
            self.last_query = {"index": index, "query": query, "size": size}
            response = self.elastic.search(
                index=index,
                query=query,
                size=size,
                source=source,
                sort=sort,
            )
            hits = response.get("hits", {})
            if not isinstance(hits, Mapping):
                raise ValueError("Elasticsearch returned invalid hits")
            total = _total_value(hits.get("total", 0))
            raw_hits = hits.get("hits", [])
            if not isinstance(raw_hits, list):
                raise ValueError("Elasticsearch returned invalid hits")
            events = [
                normalizer(hit)
                for hit in raw_hits
                if isinstance(hit, Mapping) and isinstance(hit.get("_source", {}), Mapping)
            ]
            return ToolResult(
                tool_name=name,
                ok=True,
                data={
                    "total_events": total,
                    "returned_events": len(events),
                    "sampled": total > len(events),
                    "sampling": {
                        "ordered_by": ["@timestamp", "_shard_doc"],
                        "limit": size,
                        "note": "Returned events are a deterministic bounded sample, not all matches."
                    },
                    "omitted_fields": [
                        "agent.*",
                        "ecs.*",
                        "input.*",
                        "log.*",
                        "observer.*",
                        "os.*",
                        "unmapped source fields",
                    ],
                    "events": events,
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
                normalizer=lambda hit: compact_event(hit.get("_source", {})),
                source=_EVENT_SOURCE_FIELDS,
                sort=[{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
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
                "common_paths": {"terms": {"field": "url.original", "size": 10}},
                "user_agents": {"terms": {"field": "user_agent.original", "size": 10}},
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
                data=_compact_http_statistics(response),
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
                normalizer=lambda hit: compact_alert(
                    str(hit.get("_id", "")), hit.get("_source", {})
                ),
                source=_ALERT_SOURCE_FIELDS,
                sort=[{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
            )
        except ValueError as exc:
            return ToolResult(tool_name="get_related_alerts", ok=False, error=str(exc))


TOOL_NAMES = (
    "search_elasticsearch",
    "discover_fields",
    "get_source_activity",
    "get_http_statistics",
    "get_related_alerts",
)


def tool_definitions() -> list[dict[str, Any]]:
    """Return Responses API function definitions for the approved tools."""
    return [
        {
            "type": "function",
            "name": "search_elasticsearch",
            "description": (
                "Run a validated read-only Elasticsearch Query DSL search or aggregation. "
                "Choose the index, filters, time range, fields, grouping, and statistics. "
                "Results are compact and bounded; use discover_fields first when needed."
            ),
            "parameters": ElasticsearchSearchArgs.model_json_schema(),
            "strict": False,
        },
        {
            "type": "function",
            "name": "discover_fields",
            "description": (
                "Discover searchable and aggregatable field names and types for a configured "
                "Elasticsearch index. Results are bounded."
            ),
            "parameters": strict_json_schema(DiscoverFieldsArgs),
            "strict": True,
        },
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
