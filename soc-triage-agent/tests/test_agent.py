import json
from datetime import datetime, timezone
from unittest.mock import Mock

from src.agent import TriageAgent
from src.config import Settings
from src.elastic_client import ElasticClient
from src.observability import sanitize
from src.prompts import alert_input
from src.schemas import AlertContext, ToolResult
from src.tools import InvestigationTools


def alert() -> AlertContext:
    return AlertContext(
        alert_id="alert-1",
        rule_name="Test rule",
        detected_at=datetime.now(timezone.utc),
        source_ip="192.0.2.10",
        severity="low",
    )


def response(output, output_text=None, response_id=None):
    result = Mock(output=output, output_text=output_text)
    if response_id is not None:
        result.id = response_id
    return result


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
        response([function_call("search_elasticsearch", {
            "index": "logs-*",
            "query": {"term": {"source.ip": "192.0.2.10"}},
            "source_fields": ["@timestamp", "source.ip"],
            "size": 2,
        })], response_id="response-1"),
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
    tools.search_elasticsearch.return_value = ToolResult(
        tool_name="search_elasticsearch", ok=True, data={"total_hits": 2, "columns": [], "rows": []}
    )
    report = TriageAgent(settings(log_llm_requests=True), tools, openai).run(alert())

    assert report.assessment == "true_positive"
    assert report.proposed_action == "ESCALATE"
    assert report.execution_status == "completed"
    assert report.tool_call_count == 1
    assert report.model_request_count == 2
    assert openai.responses.create.call_count == 2
    assert tools.search_elasticsearch.call_count == 1


def test_unknown_tool_and_invalid_arguments_are_returned_to_model() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([
            function_call("not_allowed", {}),
            function_call("get_http_statistics", {}, "call-2"),
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
    assert "unknown tool" in follow_up[3]["output"]


def test_malformed_model_output_and_budget_exhaustion_escalate_safely() -> None:
    malformed_client = Mock()
    malformed_client.responses.create.return_value = response([], "not-json")
    malformed = TriageAgent(settings(), Mock(), malformed_client).run(alert())
    assert malformed.assessment == "uncertain"
    assert malformed.proposed_action == "ESCALATE"
    assert malformed.execution_status == "failed"

    budget_client = Mock()
    budget_client.responses.create.return_value = response([function_call("unknown", {})])
    budget = TriageAgent(settings(max_tool_calls=1), Mock(), budget_client).run(alert())
    assert budget.assessment == "uncertain"
    assert budget.proposed_action == "ESCALATE"
    assert budget.execution_status == "failed"


def test_invalid_window_is_returned_and_valid_retry_can_continue_with_previous_response() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "not-approved",
            "query": {"match_all": {}},
        })], response_id="response-1"),
        response([function_call("search_elasticsearch", {
            "index": "logs-*",
            "query": {"match_all": {}},
        }, "call-2")], response_id="response-2"),
        response([], json.dumps({
            "assessment": "true_positive",
            "severity": "medium",
            "confidence": 0.8,
            "summary": "The bounded evidence supports the detection.",
            "evidence": ["two events"],
            "missing_evidence": [],
            "recommended_next_steps": [],
        }), response_id="response-3"),
    ]
    elastic = Mock()
    elastic.search.return_value = {"hits": {"total": {"value": 2}, "hits": []}}
    tools = InvestigationTools(elastic, settings(max_query_window_minutes=30))

    report = TriageAgent(settings(max_query_window_minutes=30), tools, openai).run(alert())

    assert report.execution_status == "completed"
    assert report.assessment == "true_positive"
    assert report.tool_call_count == 2
    assert elastic.search.call_count == 1
    assert '"logs-*"' in openai.responses.create.call_args_list[0].kwargs["input"]
    assert '".alerts-security.alerts-default"' in openai.responses.create.call_args_list[0].kwargs["input"]
    second_request = openai.responses.create.call_args_list[1].kwargs
    assert second_request["previous_response_id"] == "response-1"
    assert second_request["input"] == [{
        "type": "function_call_output",
        "call_id": "call-1",
        "output":         '{"tool_name":"search_elasticsearch","ok":false,"data":{},"error":"index \'not-approved\' is not authorized; permitted index patterns: logs-*, logs-nginx.access-*, .alerts-security.alerts-default"}',
    }]
    third_request = openai.responses.create.call_args_list[2].kwargs
    assert third_request["previous_response_id"] == "response-2"
    assert third_request["input"][0]["call_id"] == "call-2"


def test_openai_api_failure_is_a_failed_uncertain_investigation() -> None:
    openai = Mock()
    openai.responses.create.side_effect = RuntimeError("API unavailable")

    report = TriageAgent(settings(), Mock(), openai).run(alert())

    assert report.execution_status == "failed"
    assert report.assessment == "uncertain"
    assert report.proposed_action == "ESCALATE"
    assert report.model_request_count == 1


def test_follow_up_openai_payload_contains_compact_tool_evidence() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "logs-*",
            "query": {"match_all": {}},
            "source_fields": ["@timestamp", "process.name", "process.command_line"],
            "size": 10,
        })], response_id="response-1"),
        response([], json.dumps({
            "assessment": "uncertain",
            "severity": "low",
            "confidence": 0.4,
            "summary": "The compact evidence is insufficient.",
            "evidence": ["A process event was observed."],
            "missing_evidence": [],
            "recommended_next_steps": [],
        })),
    ]
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{
                "_id": "event-1",
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "source.ip": "192.0.2.10",
                    "process.name": "powershell.exe",
                    "process.command_line": "powershell -enc suspicious",
                    "agent": {"name": "filebeat"},
                    "ecs": {"version": "8.0.0"},
                    "message": "raw document " * 100,
                },
            }],
        }
    }
    tools = InvestigationTools(elastic, settings())

    report = TriageAgent(settings(), tools, openai).run(alert())

    assert report.execution_status == "completed"
    follow_up_input = openai.responses.create.call_args_list[1].kwargs["input"]
    tool_output = follow_up_input[0]["output"]
    assert "powershell.exe" in tool_output
    assert "filebeat" not in tool_output
    assert "raw document" not in tool_output
    assert "unrequested source fields" in tool_output


def test_follow_up_openai_payload_contains_compact_field_discovery() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("discover_fields", {
            "index": "logs-*",
            "field_prefix": "process.",
            "max_fields": 2,
        })], response_id="response-1"),
        response([], json.dumps({
            "assessment": "uncertain",
            "severity": "low",
            "confidence": 0,
            "summary": "Insufficient evidence.",
            "evidence": [],
            "missing_evidence": [],
            "recommended_next_steps": [],
        })),
    ]
    elastic = Mock()
    elastic.field_caps.return_value = {
        "fields": {
            "process.name": {"keyword": {"searchable": True, "aggregatable": True}},
            "process.pid": {"long": {"searchable": True, "aggregatable": True}},
        }
    }

    report = TriageAgent(settings(), InvestigationTools(elastic, settings()), openai).run(alert())

    assert report.execution_status == "completed"
    output = openai.responses.create.call_args_list[1].kwargs["input"][0]["output"]
    assert '"columns":["field","type","searchable","aggregatable"]' in output
    assert '"rows":[["process.name","keyword",true,true],["process.pid","long",true,true]]' in output
    assert '"types"' not in output


def test_initial_context_limits_rule_description() -> None:
    context = alert_input(
        AlertContext(
            alert_id="alert-1",
            rule_description="rule detail " * 500,
        ),
        max_query_window_minutes=30,
    )

    assert "[description omitted]" in context
    assert context.count("rule detail") == 100


def test_initial_context_includes_compact_alert_telemetry_provenance() -> None:
    context = alert_input(
        AlertContext(
            alert_id="alert-1",
            telemetry_datasets=["endpoint.events"],
            originating_indices=["logs-endpoint.events-*"],
            telemetry_provenance="known",
        ),
        max_query_window_minutes=30,
    )

    assert '"telemetry_datasets": [' in context and "endpoint.events" in context
    assert '"originating_indices": [' in context and "logs-endpoint.events-*" in context
    assert "Use known originating datasets first" in context


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
    }), response_id="response-2"),

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
    assert [tool["name"] for tool in payload["tools"]] == [
        "search_elasticsearch",
        "discover_fields",
    ]
    for tool in payload["tools"]:
        schema = tool["parameters"]
        if tool["strict"]:
            assert schema["additionalProperties"] is False
            assert set(schema["required"]) == set(schema["properties"])
            assert "default" not in schema["properties"].get("max_events", {})
    generic = next(tool for tool in payload["tools"] if tool["name"] == "search_elasticsearch")
    assert generic["strict"] is False
    assert generic["parameters"]["properties"]["query"]["type"] == "object"
    output_schema = payload["text"]["format"]["schema"]
    assert output_schema["additionalProperties"] is False
    assert set(output_schema["required"]) == set(output_schema["properties"])
    assert output_schema["properties"]["evidence"]["type"] == "array"
