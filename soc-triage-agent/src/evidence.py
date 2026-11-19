"""Generic bounded evidence normalization for SIEM results."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


MAX_REPRESENTATIVE_VALUES = 10
MAX_TEXT_LENGTH = 4000
MAX_EVIDENCE_FIELDS = 200

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
    "custom",
    "detection",
    "esql",
    "eql",
    "indicator",
    "observables",
    "security",
    "signal",
    "threat",
}
_ALLOWED_EVIDENCE_PREFIXES = (
    "@timestamp",
    "event.",
    "host.",
    "user.",
    "process.",
    "source.",
    "destination.",
    "client.",
    "server.",
    "network.",
    "dns.",
    "http.",
    "url.",
    "user_agent.",
    "file.",
    "authentication.",
    "custom.",
    "detection.",
    "indicator.",
    "observables.",
    "security.",
    "signal.",
    "registry.",
    "dll.",
    "package.",
    "cloud.",
    "container.",
    "orchestrator.",
    "threat.",
    "vulnerability.",
    "tls.",
    "x509.",
    "email.",
    "rule.",
    "winlog.",
    "powershell.",
    "m365.",
    "azure.",
    "aws.",
    "gcp.",
    "o365.",
)


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


def compact_event(
    source: Mapping[str, Any],
    selected_fields: list[str] | None = None,
) -> dict[str, Any]:
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
    if selected_fields:
        selected: dict[str, Any] = {}
        for field_name in sorted(set(selected_fields)):
            if "*" in field_name:
                continue
            value = field(source, *field_name.split("."))
            if value is not None:
                selected[field_name] = _compact_scalar(value)
        if selected:
            result["selected_fields"] = selected
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


def compact_detection_evidence(
    source: Mapping[str, Any],
    *,
    max_text_length: int = MAX_TEXT_LENGTH,
    max_fields: int = MAX_EVIDENCE_FIELDS,
) -> dict[str, Any]:
    """Keep useful ECS and detection-specific evidence without Elastic rule metadata."""
    event_count: int | float | None = None
    distinct_url_count: int | float | None = None
    url_values: list[str] = []
    custom: dict[str, Any] = {}
    evidence: dict[str, Any] = {}

    def flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
        if isinstance(value, Mapping):
            fields: list[tuple[str, Any]] = []
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(child, Mapping):
                    fields.extend(flatten(child, name))
                else:
                    fields.append((name, child))
            return fields
        return [(prefix, value)] if prefix else []

    def blocked(name: str) -> bool:
        lower = name.lower()
        return (
            lower.startswith("kibana.")
            or lower.startswith("elastic_agent.")
            or lower.startswith("ecs.")
            or lower.startswith("log.")
            or lower.startswith("observer.")
            or lower.startswith("agent.")
            or lower.startswith("input.")
            or lower.startswith("event.ingested")
            or lower.startswith("event.created")
            or lower.startswith("_")
        )

    for name, value in flatten(source):
        lower = name.lower()
        if blocked(name):
            continue
        normalized = lower.replace(".", "_")
        if normalized.endswith("event_count") and isinstance(value, (int, float)):
            event_count = value
        elif normalized.endswith("url_original_count_distinct") and isinstance(value, (int, float)):
            distinct_url_count = value
        elif "url_original" in normalized and isinstance(value, list):
            url_values.extend(item for item in value if isinstance(item, str))

        top_namespace = name.split(".", 1)[0].lower()
        allowed = name.startswith(_ALLOWED_EVIDENCE_PREFIXES)
        custom_namespace = (
            top_namespace in _EVIDENCE_NAMESPACES
            or top_namespace in {"esql", "eql"}
        )
        if allowed:
            if len(evidence) >= max_fields:
                evidence["_omitted_fields"] = int(evidence.get("_omitted_fields", 0)) + 1
                continue
            evidence[name] = _compact_scalar(
                value,
                max_text_length=max_text_length,
                max_fields=max_fields,
            )

    for top_name, child in source.items():
        top_namespace = str(top_name).lower()
        if top_namespace in _EVIDENCE_NAMESPACES or top_namespace in {"esql", "eql"}:
            bounded = _bounded_value(
                child,
                max_text_length=max_text_length,
                max_fields=max_fields,
                skip_tokens={"event_count", "url_original"},
            )
            if isinstance(bounded, Mapping) and any(
                not str(key).startswith("_") for key in bounded
            ):
                custom[top_namespace] = bounded
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


def _compact_scalar(
    value: Any,
    *,
    max_text_length: int = MAX_TEXT_LENGTH,
    max_fields: int = MAX_EVIDENCE_FIELDS,
) -> Any:
    if isinstance(value, str):
        if len(value) <= max_text_length:
            return value
        return f"{value[:max_text_length]}… [omitted {len(value) - max_text_length} characters]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        values = [
            _compact_scalar(
                item,
                max_text_length=max_text_length,
                max_fields=max_fields,
            )
            for item in value
        ]
        ordered = sorted(values, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        result: dict[str, Any] = {
            "count": len(values),
            "representative": ordered[:MAX_REPRESENTATIVE_VALUES],
        }
        if len(values) > MAX_REPRESENTATIVE_VALUES:
            result["omitted_count"] = len(values) - MAX_REPRESENTATIVE_VALUES
        return result
    if isinstance(value, Mapping):
        return _bounded_value(
            value,
            max_text_length=max_text_length,
            max_fields=max_fields,
        )
    return str(value)


def _bounded_value(
    value: Any,
    skip_tokens: set[str] | None = None,
    *,
    max_text_length: int = MAX_TEXT_LENGTH,
    max_fields: int = MAX_EVIDENCE_FIELDS,
) -> Any:
    if not isinstance(value, Mapping):
        return _compact_scalar(
            value,
            max_text_length=max_text_length,
            max_fields=max_fields,
        )
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
        if len(result) >= max_fields:
            omitted += 1
            continue
        result[str(key)] = (
            _bounded_value(
                child,
                skip_tokens=skip_tokens,
                max_text_length=max_text_length,
                max_fields=max_fields,
            )
            if isinstance(child, Mapping)
            else _compact_scalar(
                child,
                max_text_length=max_text_length,
                max_fields=max_fields,
            )
        )
    if omitted:
        result["_omitted_fields"] = omitted
    return result
