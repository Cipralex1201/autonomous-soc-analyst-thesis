import json
from datetime import datetime, timezone
from unittest.mock import Mock

from elastic_transport import TransportError

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


def test_model_budget_reserves_a_no_tools_finalization_request() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "logs-*", "query": {"match_all": {}},
        })], response_id="response-1"),
        response([], json.dumps({
            "assessment": "true_positive",
            "severity": "medium",
            "confidence": 0.7,
            "summary": "Collected evidence supports the alert.",
            "evidence": ["query result"],
            "missing_evidence": ["authorization context"],
            "recommended_next_steps": [],
        })),
    ]
    tools = Mock()
    tools.search_elasticsearch.return_value = ToolResult(
        tool_name="search_elasticsearch", ok=True, data={"total_hits": 1}
    )

    report = TriageAgent(settings(max_model_requests=2), tools, openai).run(alert())

    assert report.execution_status == "partial"
    assert report.provisional is True
    assert report.finalization_triggered_by_budget is True
    assert report.assessment == "true_positive"
    assert report.proposed_action == "ESCALATE"
    assert report.tool_results[0].data["total_hits"] == 1
    assert openai.responses.create.call_args_list[1].kwargs["tools"] == []


def test_tool_budget_finalization_preserves_failed_and_successful_results() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "logs-*", "query": {"match_all": {}},
        }), function_call("discover_fields", {
            "index": "logs-*", "field_prefix": "process.",
        }, "call-2")], response_id="response-1"),
        response([], json.dumps({
            "assessment": "uncertain",
            "severity": "low",
            "confidence": 0.2,
            "summary": "The investigation was incomplete.",
            "evidence": [],
            "missing_evidence": ["More telemetry"],
            "recommended_next_steps": [],
        })),
    ]

    report = TriageAgent(settings(max_tool_calls=1), Mock(), openai).run(alert())

    assert report.execution_status == "partial"
    assert report.tool_call_count == 0
    assert report.finalization_reason == "SIEM tool-call budget exhausted"
    assert openai.responses.create.call_args_list[1].kwargs["tools"] == []


def test_finalization_failure_preserves_accumulated_evidence() -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "logs-*", "query": {"match_all": {}},
        })], response_id="response-1"),
        RuntimeError("finalization unavailable"),
    ]
    tools = Mock()
    tools.search_elasticsearch.return_value = ToolResult(
        tool_name="search_elasticsearch", ok=True, data={"total_hits": 3}
    )

    report = TriageAgent(settings(max_model_requests=2), tools, openai).run(alert())

    assert report.execution_status == "failed"
    assert report.tool_results[0].data["total_hits"] == 3
    assert report.error == "finalization unavailable"


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
    assert generic["parameters"]["properties"]["size"]["minimum"] == 0
    assert "size=0" in generic["description"]
    assert "small bounded sample" in generic["description"]
    assert "Use size=0" in payload["instructions"]
    assert "concrete investigative question" in payload["instructions"]
    output_schema = payload["text"]["format"]["schema"]
    assert output_schema["additionalProperties"] is False
    assert set(output_schema["required"]) == set(output_schema["properties"])
    assert output_schema["properties"]["evidence"]["type"] == "array"


def test_trace_keeps_auditable_sequence_without_duplicate_sdk_response_or_ciphertext(tmp_path) -> None:
    openai = Mock()
    first = {
        "output": [
            {
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "Check the matching events."}],
                "encrypted_content": "opaque-reasoning-payload",
            },
            function_call(
                "search_elasticsearch",
                {
                    "index": "logs-*",
                    "query": {"term": {"source.ip": "192.0.2.10"}},
                    "aggregations": {
                        "by_status": {
                            "terms": {"field": "http.response.status_code", "size": 5}
                        }
                    },
                    "source_fields": ["@timestamp", "source.ip"],
                    "size": 1,
                },
            ),
        ],
        "output_text": None,
        "id": "response-1",
        "status": "completed",
        "model": "test-model",
        "usage": {
            "input_tokens": 20,
            "output_tokens": 8,
            "total_tokens": 28,
            "input_tokens_details": {"cached_tokens": 5},
            "output_tokens_details": {"reasoning_tokens": 3},
        },
    }
    final = {
        "output": [],
        "output_text": json.dumps({
            "assessment": "true_positive",
            "severity": "medium",
            "confidence": 0.8,
            "summary": "The evidence supports the detection.",
            "evidence": ["A matching event was observed."],
            "missing_evidence": [],
            "recommended_next_steps": [],
        }),
        "id": "response-2",
        "status": "completed",
        "model": "test-model",
        "usage": {},
    }
    openai.responses.create.side_effect = [first, final]

    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 2},
            "hits": [{
                "_id": "event-1",
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "source.ip": "192.0.2.10",
                },
            }],
        },
        "aggregations": {
            "by_status": {
                "buckets": [{"key": 200, "doc_count": 2}]
            }
        },
    }
    runtime_settings = settings(
        investigation_trace_directory=str(tmp_path),
        investigation_trace_elastic_enabled=False,
    )
    report = TriageAgent(runtime_settings, InvestigationTools(elastic, runtime_settings), openai).run(alert())

    events = [
        json.loads(line)
        for line in next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8").splitlines()
    ]
    response_event = next(event for event in events if event["event_type"] == "llm.response")
    tool_event = next(event for event in events if event["event_type"] == "tool.completed")
    tool_called = next(event for event in events if event["event_type"] == "tool.called")
    request_events = [event for event in events if event["event_type"] == "llm.request"]
    output = response_event["llm"]["output"]

    assert report.assessment == "true_positive"
    assert "response" not in response_event["llm"]
    assert response_event["response_id"] == "response-1"
    assert response_event["status"] == "completed"
    assert response_event["model_request_number"] == 1
    assert response_event["input_tokens"] == 20
    assert response_event["output_tokens"] == 8
    assert response_event["total_tokens"] == 28
    assert response_event["cached_input_tokens"] == 5
    assert response_event["reasoning_output_tokens"] == 3
    assert response_event["api_latency_seconds"] >= 0
    assert response_event["llm"]["metadata"]["model"] == "test-model"
    assert output[0]["summary"][0]["text"] == "Check the matching events."
    assert "encrypted_content" not in output[0]
    assert output[1]["arguments"] == (
        '{"index": "logs-*", "query": {"term": {"source.ip": "192.0.2.10"}}, '
        '"aggregations": {"by_status": {"terms": {"field": "http.response.status_code", "size": 5}}}, '
        '"source_fields": ["@timestamp", "source.ip"], "size": 1}'
    )
    assert request_events[0]["llm"]["parameters"]["instructions"]
    assert request_events[0]["llm"]["parameters"]["tools"]
    assert request_events[1]["llm"]["parameters"]["previous_response_id"] == "response-1"
    assert request_events[1]["llm"]["parameters"]["input"][0]["type"] == "function_call_output"
    assert tool_event["tool_name"] == "search_elasticsearch"
    assert tool_event["tool_status"] == "completed"
    assert tool_event["tool_call_number"] == 1
    assert tool_event["total_hits"] == 2
    assert tool_event["returned_hits"] == 1
    assert tool_event["result_size_bytes"] > 0
    assert tool_event["sampled"] is True
    assert tool_event["truncated"] is False
    assert tool_event["aggregation_names"] == ["by_status"]
    assert tool_called["tool"]["requested_arguments"]
    assert tool_event["tool"]["validated_arguments"]["size"] == 1
    assert tool_event["tool"]["executed_elasticsearch_dsl"]["query"] == {
        "term": {"source.ip": "192.0.2.10"}
    }
    completed = next(event for event in events if event["event_type"] == "investigation.completed")
    assert completed["final"]["verdict"]["assessment"] == "true_positive"
    assert "opaque-reasoning-payload" not in json.dumps(events)


def test_trace_classifies_tool_argument_rejection_and_preserves_validated_args(tmp_path) -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "logs-*",
            "query": {"range": {"@timestamp": {"gte": "now-1h", "invalid": "now"}}},
            "size": 0,
        })], response_id="response-1"),
        response([], json.dumps({
            "assessment": "uncertain",
            "severity": "low",
            "confidence": 0,
            "summary": "The query was rejected.",
            "evidence": [],
            "missing_evidence": ["A valid search result"],
            "recommended_next_steps": [],
        })),
    ]
    runtime_settings = settings(
        investigation_trace_directory=str(tmp_path),
        investigation_trace_elastic_enabled=False,
    )
    report = TriageAgent(runtime_settings, InvestigationTools(Mock(), runtime_settings), openai).run(alert())

    events = [
        json.loads(line)
        for line in next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8").splitlines()
    ]
    failure = next(event for event in events if event["event_type"] == "tool.failed")

    assert report.assessment == "uncertain"
    assert failure["tool_name"] == "search_elasticsearch"
    assert failure["tool_status"] == "failed"
    assert failure["tool_call_number"] == 1
    assert failure["failure_category"] == "validation"
    assert failure["tool"]["requested_arguments"]
    assert failure["tool"]["validated_arguments"]["size"] == 0
    assert failure["tool"]["executed_elasticsearch_dsl"] is None


def test_trace_indexes_elasticsearch_execution_failure_category(tmp_path) -> None:
    openai = Mock()
    openai.responses.create.side_effect = [
        response([function_call("search_elasticsearch", {
            "index": "logs-*",
            "query": {"match_all": {}},
        })], response_id="response-1"),
        response([], json.dumps({
            "assessment": "uncertain",
            "severity": "low",
            "confidence": 0,
            "summary": "The search failed.",
            "evidence": [],
            "missing_evidence": ["Search results"],
            "recommended_next_steps": [],
        })),
    ]
    elastic = Mock()
    elastic.search.side_effect = TransportError("simulated transport failure")
    runtime_settings = settings(
        investigation_trace_directory=str(tmp_path),
        investigation_trace_elastic_enabled=False,
    )

    report = TriageAgent(runtime_settings, InvestigationTools(elastic, runtime_settings), openai).run(alert())

    events = [
        json.loads(line)
        for line in next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8").splitlines()
    ]
    failure = next(event for event in events if event["event_type"] == "tool.failed")

    assert report.assessment == "uncertain"
    assert failure["failure_category"] == "execution"
    assert failure["error"]["stage"] == "execution"
    assert failure["duration_seconds"] >= 0
    assert failure["result_size_bytes"] > 0
