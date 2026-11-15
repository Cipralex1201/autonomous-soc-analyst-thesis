"""Generic bounded evidence normalization for SIEM results."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


MAX_REPRESENTATIVE_VALUES = 10
MAX_EVIDENCE_FIELDS = 24
MAX_TEXT_LENGTH = 300

_NOISY_NAMESPACES = {
    "agent",
    "ecs",
    "elastic_agent",
    "input",
    "log",
    "observer",
    "os",
}
_EVIDENCE_NAMESPACES = {
    "authentication",
    "detection",
    "esql",
    "threat",
}


def field(source: Mapping[str, Any], *path: str) -> Any:
    """Read ECS fields from either dotted or nested Elasticsearch sources."""
    dotted = ".".join(path)
    if dotted in source:
        return source[dotted]
    value: Any = source
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def compact_event(source: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize an event to useful ECS and detection evidence fields."""
    result: dict[str, Any] = {}
    fields = {
        "timestamp": ("@timestamp",),
        "event_id": ("event", "id"),
        "event_kind": ("event", "kind"),
        "event_category": ("event", "category"),
        "event_action": ("event", "action"),
        "event_type": ("event", "type"),
        "event_outcome": ("event", "outcome"),
        "source_ip": ("source", "ip"),
        "source_port": ("source", "port"),
        "destination_ip": ("destination", "ip"),
        "destination_port": ("destination", "port"),
        "host": ("host", "name"),
        "user": ("user", "name"),
        "http_method": ("http", "request", "method"),
        "url_original": ("url", "original"),
        "url_path": ("url", "path"),
        "status_code": ("http", "response", "status_code"),
        "user_agent": ("user_agent", "original"),
        "process_name": ("process", "name"),
        "process_executable": ("process", "executable"),
        "process_command_line": ("process", "command_line"),
        "file_name": ("file", "name"),
        "file_path": ("file", "path"),
        "dns_question": ("dns", "question", "name"),
        "dns_question_type": ("dns", "question", "type"),
        "network_protocol": ("network", "protocol"),
        "network_transport": ("network", "transport"),
        "authentication_outcome": ("authentication", "outcome"),
    }
    for output_name, path in fields.items():
        value = field(source, *path)
        if value is not None:
            result[output_name] = _compact_scalar(value)

    evidence = compact_detection_evidence(source)
    if evidence:
        result["detection_evidence"] = evidence
    return result


def compact_alert(alert_id: str, source: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a related alert without exposing its rule document."""
    result: dict[str, Any] = {
        "alert_id": alert_id,
        "rule_name": field(source, "kibana", "alert", "rule", "name")
        or field(source, "kibana", "alert", "rule", "rule_name"),
        "timestamp": field(source, "@timestamp")
        or field(source, "kibana", "alert", "original_time"),
        "severity": field(source, "kibana", "alert", "severity"),
        "source_ip": field(source, "source", "ip"),
        "host": field(source, "host", "name"),
    }
    evidence = compact_detection_evidence(source)
    if evidence:
        result["detection_evidence"] = evidence
    return {
        key: value if key == "detection_evidence" else _compact_scalar(value)
        for key, value in result.items()
        if value is not None
    }


def compact_detection_evidence(source: Mapping[str, Any]) -> dict[str, Any]:
    """Keep useful detection statistics and bounded custom evidence."""
    event_count: int | float | None = None
    distinct_url_count: int | float | None = None
    url_values: list[str] = []
    custom: dict[str, Any] = {}

    def visit(value: Any, namespace: str | None = None) -> None:
        nonlocal event_count, distinct_url_count
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_text = str(key)
                normalized = key_text.lower().replace(".", "_")
                child_namespace = namespace or normalized
                if normalized.endswith("event_count") and isinstance(child, (int, float)):
                    event_count = child
                elif normalized.endswith("url_original_count_distinct") and isinstance(child, (int, float)):
                    distinct_url_count = child
                elif "url_original" in normalized and isinstance(child, list):
                    url_values.extend(item for item in child if isinstance(item, str))
                if (
                    namespace is None
                    and
                    child_namespace in _EVIDENCE_NAMESPACES
                    and child_namespace not in _NOISY_NAMESPACES
                    and child_namespace not in custom
                ):
                    bounded = _bounded_value(
                        child,
                        skip_tokens={"event_count", "url_original"},
                    )
                    if not (
                        isinstance(bounded, Mapping)
                        and not any(not str(key).startswith("_") for key in bounded)
                    ):
                        custom[child_namespace] = bounded
                visit(child, child_namespace)
        elif isinstance(value, list):
            for item in value:
                visit(item, namespace)

    visit(source)
    evidence: dict[str, Any] = {}
    if event_count is not None:
        evidence["event_count"] = event_count
    if distinct_url_count is not None:
        evidence["url_original_count_distinct"] = distinct_url_count
    if url_values:
        paths = sorted(set(url_values))
        evidence["url_path_total_count"] = (
            distinct_url_count if distinct_url_count is not None else len(paths)
        )
        evidence["representative_url_paths"] = paths[:MAX_REPRESENTATIVE_VALUES]
        if len(paths) > MAX_REPRESENTATIVE_VALUES:
            evidence["url_paths_omitted_count"] = len(paths) - MAX_REPRESENTATIVE_VALUES
    if custom:
        evidence["custom"] = custom
    return evidence


def _compact_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= MAX_TEXT_LENGTH else f"{value[:MAX_TEXT_LENGTH]}… [omitted]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        values = [_compact_scalar(item) for item in value]
        ordered = sorted(values, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        result: dict[str, Any] = {
            "count": len(values),
            "representative": ordered[:MAX_REPRESENTATIVE_VALUES],
        }
        if len(values) > MAX_REPRESENTATIVE_VALUES:
            result["omitted_count"] = len(values) - MAX_REPRESENTATIVE_VALUES
        return result
    if isinstance(value, Mapping):
        return _bounded_value(value)
    return str(value)


def _bounded_value(value: Any, skip_tokens: set[str] | None = None) -> Any:
    if not isinstance(value, Mapping):
        return _compact_scalar(value)
    items = sorted(value.items(), key=lambda item: str(item[0]))
    result: dict[str, Any] = {}
    omitted = 0
    for key, child in items:
        normalized_key = str(key).lower()
        if (
            normalized_key in _NOISY_NAMESPACES
            or (skip_tokens and any(token in normalized_key for token in skip_tokens))
        ):
            omitted += 1
            continue
        if len(result) >= MAX_EVIDENCE_FIELDS:
            omitted += 1
            continue
        result[str(key)] = (
            _bounded_value(child, skip_tokens=skip_tokens)
            if isinstance(child, Mapping)
            else _compact_scalar(child)
        )
    if omitted:
        result["_omitted_fields"] = omitted
    return result
