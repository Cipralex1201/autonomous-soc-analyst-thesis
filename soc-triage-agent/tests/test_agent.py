import json
from datetime import datetime, timezone
from unittest.mock import Mock

from src.agent import TriageAgent
from src.config import Settings
from src.observability import sanitize
from src.schemas import AlertContext, ToolResult
from src.elastic_client import ElasticClient


def alert() -> AlertContext:
    return AlertContext(
        alert_id="alert-1",
        rule_name="Test rule",
        detected_at=datetime.now(timezone.utc),
        source_ip="192.0.2.10",
        severity="low",
    )


def response(output, output_text=None):
    return Mock(output=output, output_text=output_text)


def function_call(name, arguments, call_id="call-1"):
    return {"type": "function_call", "name": name, "arguments": json.dumps(arguments), "call_id": call_id}


def settings(**overrides) -> Settings:
    return Settings(
        openai_api_key="test-key",
        openai_model="test-model",
        prompt_inspection_mode="off",
        **overrides,
    )


def test_agent_supports_sequential_tool_calling_and_maps_action() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("get_source_activity", {
            "source_ip": "192.0.2.10",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-01T00:01:00Z",
            "max_events": 2,
        })]),
        response([], json.dumps({
            "assessment": "true_positive",
            "severity": "medium",
            "confidence": 0.9,
            "summary": "Suspicious activity is supported.",
            "evidence": ["two events"],
            "missing_evidence": [],
            "recommended_next_steps": ["Review authorization"],
        })),
    ]
    tools = Mock()
    tools.get_source_activity.return_value = ToolResult(
        tool_name="get_source_activity", ok=True, data={"total": {"value": 2}, "events": []}
    )
    report = TriageAgent(settings(log_llm_requests=True), tools, openai).run(alert())

    assert report.assessment == "true_positive"
    assert report.proposed_action == "ESCALATE"
    assert report.tool_call_count == 1
    assert report.model_request_count == 2
    assert openai.responses.create.call_count == 2
    assert tools.get_source_activity.call_count == 1


def test_unknown_tool_and_invalid_arguments_are_returned_to_model() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([
            function_call("not_allowed", {}),
            function_call("get_http_statistics", {"source_ip": "not-an-ip", "start": "bad", "end": "bad"}, "call-2"),
        ]),
        response([], json.dumps({
            "assessment": "uncertain",
            "severity": "unknown",
            "confidence": 0,
            "summary": "Insufficient evidence.",
            "evidence": [],
            "missing_evidence": ["Tool validation failed"],
            "recommended_next_steps": [],
        })),
    ]
    report = TriageAgent(settings(), Mock(), openai).run(alert())

    assert report.assessment == "uncertain"
    assert report.proposed_action == "ESCALATE"
    follow_up = openai.responses.create.call_args_list[1].kwargs["input"]
    assert "unknown tool" in follow_up[2]["output"]
    assert "invalid tool arguments" in follow_up[3]["output"]


def test_malformed_model_output_and_budget_exhaustion_escalate_safely() -> None:
    malformed_client = Mock()
    malformed_client.responses.create.return_value = response([], "not-json")
    malformed = TriageAgent(settings(), Mock(), malformed_client).run(alert())
    assert malformed.assessment == "uncertain"
    assert malformed.proposed_action == "ESCALATE"

    budget_client = Mock()
    budget_client.responses.create.return_value = response([function_call("unknown", {})])
    budget = TriageAgent(settings(max_tool_calls=1), Mock(), budget_client).run(alert())
    assert budget.assessment == "uncertain"
    assert budget.proposed_action == "ESCALATE"


def test_sensitive_values_are_redacted() -> None:
    result = sanitize({"api_key": "secret", "headers": {"authorization": "Bearer secret"}, "value": "ok"})
    assert result == {"api_key": "[REDACTED]", "headers": {"authorization": "[REDACTED]"}, "value": "ok"}


def test_large_alert_request_uses_compact_detection_context() -> None:
    source = {
        "kibana.alert.rule.name": "Generic web anomaly",
        "kibana.alert.rule.description": "Detects unusual web activity.",
        "@timestamp": "2026-01-01T00:00:00Z",
        "kibana.alert.severity": "high",
        "source.ip": "192.0.2.10",
        "Esql": {
            "event_count": 623,
            "url_original_count_distinct": 615,
            "url_original_values": [f"/path/{index}" for index in range(500)],
        },
        "metadata": {
            "original": {"lengthy": "Elastic investigation guide " * 100},
        },
    }
    normalized = ElasticClient.normalize_alert("large-alert", source)
    openai = Mock()
    openai.responses.create.return_value = response([], json.dumps({
        "assessment": "uncertain",
        "severity": "high",
        "confidence": 0,
        "summary": "Insufficient evidence.",
        "evidence": [],
        "missing_evidence": [],
        "recommended_next_steps": [],
    }))

    TriageAgent(settings(), Mock(), openai).run(normalized)

    payload = openai.responses.create.call_args.kwargs
    request_input = payload["input"]
    assert "metadata.original" not in request_input
    assert "Elastic investigation guide" not in request_input
    assert "event_count" in request_input and "623" in request_input
    assert "url_original_count_distinct" in request_input and "615" in request_input
    assert request_input.count("/path/") == 10
    assert len(request_input) < 3000


def test_assembled_openai_payload_uses_strict_structured_output_schemas() -> None:
    openai = Mock()
    openai.responses.create.return_value = response([], json.dumps({
        "assessment": "uncertain",
        "severity": "low",
        "confidence": 0,
        "summary": "Insufficient evidence.",
        "evidence": [],
        "missing_evidence": [],
        "recommended_next_steps": [],
    }))

    TriageAgent(settings(), Mock(), openai).run(alert())

    payload = openai.responses.create.call_args.kwargs
    for tool in payload["tools"]:
        schema = tool["parameters"]
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
        assert "default" not in schema["properties"].get("max_events", {})
    related = next(tool for tool in payload["tools"] if tool["name"] == "get_related_alerts")
    assert any(option.get("type") == "null" for option in
               related["parameters"]["properties"]["source_ip"]["anyOf"])
    output_schema = payload["text"]["format"]["schema"]
    assert output_schema["additionalProperties"] is False
    assert set(output_schema["required"]) == set(output_schema["properties"])
    assert output_schema["properties"]["evidence"]["type"] == "array"
