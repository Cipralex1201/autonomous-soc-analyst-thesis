from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from src.config import Settings
from src.schemas import (
    DiscoverFieldsArgs,
    ElasticsearchSearchArgs,
    HttpStatisticsArgs,
    RelatedAlertsArgs,
    SourceActivityArgs,
)
from src.tools import InvestigationTools


def test_http_tool_rejects_invalid_ip() -> None:
    tools = InvestigationTools(Mock(), Settings())
    result = tools.get_http_statistics(
        HttpStatisticsArgs(
            source_ip="not-an-ip",
            start=datetime.now(timezone.utc),
            end=datetime.now(timezone.utc) + timedelta(minutes=1),
        )
    )
    assert result.ok is False
    assert "valid IP" in (result.error or "")


def test_http_tool_builds_bounded_query() -> None:
    elastic = Mock()
    elastic.search.return_value = {"hits": {"total": {"value": 4, "relation": "eq"}, "hits": []}}
    tools = InvestigationTools(elastic, Settings())
    start = datetime.now(timezone.utc)
    result = tools.get_http_statistics(
        HttpStatisticsArgs(source_ip="192.0.2.10", start=start, end=start + timedelta(minutes=1))
    )
    assert result.ok is True
    assert result.data["total_requests"] == 4
    query = elastic.search.call_args.kwargs["query"]
    assert query["bool"]["filter"][1] == {"term": {"source.ip": "192.0.2.10"}}


def test_source_activity_compacts_large_filebeat_and_non_http_documents() -> None:
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 2, "relation": "eq"},
            "hits": [{
                "_id": "event-1",
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "event": {"kind": "event", "category": ["process"], "outcome": "failure"},
                    "host": {"name": "workstation-1"},
                    "user": {"name": "alice"},
                    "process": {
                        "name": "powershell.exe",
                        "command_line": "powershell -enc suspicious-command",
                    },
                    "authentication": {"outcome": "failure"},
                    "agent": {"name": "filebeat", "version": "8.0.0"},
                    "ecs": {"version": "8.0.0"},
                    "host.os": {"name": "Windows", "version": "11"},
                    "message": "large raw event " * 100,
                },
            }],
        }
    }
    tools = InvestigationTools(elastic, Settings())
    start = datetime.now(timezone.utc)

    result = tools.get_source_activity(
        SourceActivityArgs(
            source_ip="192.0.2.10",
            start=start,
            end=start + timedelta(minutes=1),
            max_events=10,
        )
    )

    event = result.data["events"][0]
    assert result.data["total_events"] == 2
    assert result.data["sampled"] is True
    assert event["process_command_line"] == "powershell -enc suspicious-command"
    assert event["authentication_outcome"] == "failure"
    assert "agent" not in event
    assert "ecs" not in event
    assert "message" not in event
    assert elastic.search.call_args.kwargs["source"]
    assert elastic.search.call_args.kwargs["sort"] == [{"@timestamp": "asc"}, {"_shard_doc": "asc"}]


def test_http_statistics_returns_readable_compact_aggregates() -> None:
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {"total": {"value": 623}},
        "aggregations": {
            "unique_paths": {"value": 615},
            "status_codes": {
                "buckets": [{"key": 404, "doc_count": 600}],
                "sum_other_doc_count": 23,
            },
            "common_paths": {
                "buckets": [{"key": "/admin", "doc_count": 18}],
                "sum_other_doc_count": 605,
            },
            "user_agents": {"buckets": [{"key": "curl", "doc_count": 623}]},
            "requests_over_time": {
                "buckets": [{"key_as_string": "2026-01-01T00:00:00Z", "doc_count": 623}]
            },
        },
    }
    tools = InvestigationTools(elastic, Settings())
    start = datetime.now(timezone.utc)

    result = tools.get_http_statistics(
        HttpStatisticsArgs(
            source_ip="192.0.2.10",
            start=start,
            end=start + timedelta(minutes=1),
        )
    )

    assert result.data["total_requests"] == 623
    assert result.data["unique_url_count"] == 615
    assert result.data["status_counts"]["values"] == [{"status_code": 404, "count": 600}]
    assert result.data["noteworthy_paths"]["values"] == [{"path": "/admin", "count": 18}]
    assert result.data["noteworthy_paths"]["omitted_count"] == 605
    assert "doc_count" not in str(result.data)
    assert "aggregations" not in result.data


def test_related_alerts_exclude_rule_guides_and_keep_detection_evidence() -> None:
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{
                "_id": "related-1",
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "kibana.alert.rule.name": "Suspicious authentication",
                    "kibana.alert.severity": "high",
                    "kibana.alert.rule.parameters": {
                        "note": "lengthy investigation guide " * 200,
                        "query": "full detection query",
                    },
                    "source.ip": "192.0.2.10",
                    "Esql": {"event_count": 4},
                },
            }],
        }
    }
    tools = InvestigationTools(elastic, Settings())
    start = datetime.now(timezone.utc)

    result = tools.get_related_alerts(
        RelatedAlertsArgs(
            source_ip="192.0.2.10",
            start=start,
            end=start + timedelta(minutes=1),
        )
    )

    related = result.data["events"][0]
    assert related == {
        "alert_id": "related-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "rule_name": "Suspicious authentication",
        "severity": "high",
        "source_ip": "192.0.2.10",
        "detection_evidence": {
            "@timestamp": "2026-01-01T00:00:00Z",
            "event_count": 4,
            "source.ip": "192.0.2.10",
        },
    }
    assert "investigation guide" not in str(result.data)
    assert "full detection query" not in str(result.data)


def test_generic_search_selects_http_filters_and_aggregations() -> None:
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 20, "relation": "eq"},
            "hits": [{
                "_id": "http-1",
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "source.ip": "192.0.2.10",
                    "http.request.method": "GET",
                    "url.path": "/admin",
                    "http.response.status_code": 404,
                },
            }],
        },
        "aggregations": {
            "by_status": {
                "buckets": [{"key": 404, "doc_count": 20}],
            }
        },
    }
    tools = InvestigationTools(elastic, Settings())
    args = ElasticsearchSearchArgs(
        index="logs-*",
        query={"bool": {"filter": [{"term": {"source.ip": "192.0.2.10"}}]}},
        aggregations={"by_status": {"terms": {"field": "http.response.status_code", "size": 5}}},
        source_fields=["@timestamp", "source.ip", "http.request.method", "url.path"],
        size=10,
    )

    result = tools.search_elasticsearch(args)

    assert result.ok is True
    assert result.data["total_hits"] == 20
    assert result.data["sampled"] is True
    assert result.data["columns"] == ["_id"]
    assert result.data["rows"][0] == ["http-1"]
    assert result.data["common_fields"] == {
        "@timestamp": "2026-01-01T00:00:00Z",
        "http.request.method": "GET",
        "source.ip": "192.0.2.10",
        "url.path": "/admin",
    }
    assert result.data["aggregations"]["by_status"]["buckets"][0] == {
        "key": 404,
        "count": 20,
    }
    request = elastic.search.call_args.kwargs
    assert request["query"] == args.query
    assert request["aggregations"] == args.aggregations
    assert request["timeout"] == "10s"


def test_generic_search_supports_authentication_and_process_datasets() -> None:
    elastic = Mock()
    elastic.search.side_effect = [
        {
            "hits": {
                "total": {"value": 1},
                "hits": [{
                    "_id": "auth-1",
                    "_source": {
                        "@timestamp": "2026-01-01T00:00:00Z",
                        "event.category": ["authentication"],
                        "event.outcome": "failure",
                        "user.name": "alice",
                    },
                }],
            }
        },
        {
            "hits": {
                "total": {"value": 1},
                "hits": [{
                    "_id": "process-1",
                    "_source": {
                        "@timestamp": "2026-01-01T00:01:00Z",
                        "event.category": ["process"],
                        "process.command_line": "curl http://example.test",
                        "process.name": "curl",
                    },
                }],
            }
        },
    ]
    tools = InvestigationTools(elastic, Settings())

    auth = tools.search_elasticsearch(ElasticsearchSearchArgs(
        index="logs-*",
        query={"term": {"event.category": "authentication"}},
        source_fields=["@timestamp", "event.category", "event.outcome", "user.name"],
    ))
    process = tools.search_elasticsearch(ElasticsearchSearchArgs(
        index="logs-*",
        query={"term": {"event.category": "process"}},
        source_fields=["@timestamp", "process.name", "process.command_line"],
    ))

    assert auth.data["rows"][0] == ["auth-1"]
    assert auth.data["common_fields"] == {
        "@timestamp": "2026-01-01T00:00:00Z",
        "event.category": {"count": 1, "representative": ["authentication"]},
        "event.outcome": "failure",
        "user.name": "alice",
    }
    assert process.data["rows"][0] == ["process-1"]
    assert process.data["common_fields"]["process.command_line"].startswith("curl ")
    assert elastic.search.call_args_list[0].kwargs["query"] != elastic.search.call_args_list[1].kwargs["query"]


def test_generic_search_allows_configured_security_alert_index() -> None:
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{
                "_id": "alert-1",
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "kibana.alert.rule.name": "Suspicious login",
                    "kibana.alert.severity": "high",
                },
            }],
        }
    }

    result = InvestigationTools(elastic, Settings()).search_elasticsearch(
        ElasticsearchSearchArgs(
            index=".alerts-security.alerts-default",
            query={"term": {"kibana.alert.severity": "high"}},
            source_fields=["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity"],
        )
    )

    assert result.ok is True
    assert result.data["common_fields"]["kibana.alert.rule.name"] == "Suspicious login"
    assert elastic.search.call_args.kwargs["index"] == ".alerts-security.alerts-default"


def test_generic_search_rejects_unsafe_queries_and_bad_sorting() -> None:
    elastic = Mock()
    tools = InvestigationTools(elastic, Settings())

    unsafe = tools.search_elasticsearch(ElasticsearchSearchArgs(
        index="logs-*",
        query={"bool": {"must": [{"script": {"source": "doc['x'].value"}}]}},
    ))
    bad_sort = tools.search_elasticsearch(ElasticsearchSearchArgs(
        index="logs-*",
        query={"match_all": {}},
        sort=[{"_id": "asc"}],
    ))
    blocked_source = tools.search_elasticsearch(ElasticsearchSearchArgs(
        index="logs-*",
        query={"match_all": {}},
        source_fields=["kibana.alert.rule.parameters.note"],
    ))

    assert unsafe.ok is False
    assert "not permitted" in (unsafe.error or "")
    assert bad_sort.ok is False
    assert "_id" in (bad_sort.error or "")
    assert blocked_source.ok is False
    assert "source field" in (blocked_source.error or "")
    elastic.search.assert_not_called()


def test_generic_search_enforces_serialized_response_limit() -> None:
    elastic = Mock()
    elastic.search.return_value = {
        "hits": {
            "total": {"value": 100},
            "hits": [{
                "_id": str(index),
                "_source": {
                    "@timestamp": "2026-01-01T00:00:00Z",
                    "process.command_line": f"suspicious command {index} " * 100,
                },
            } for index in range(25)],
        }
    }
    settings = Settings(max_tool_result_bytes=1500)
    result = InvestigationTools(elastic, settings).search_elasticsearch(
        ElasticsearchSearchArgs(
            index="logs-*",
            query={"match_all": {}},
            source_fields=["@timestamp", "process.command_line"],
            size=25,
        )
    )

    import json
    assert result.ok is True
    assert result.data["truncated"] is True
    assert result.data["omitted_hit_count"] == 25
    assert len(json.dumps(result.data, separators=(",", ":"))) <= 1500


def test_field_discovery_is_bounded_and_reports_truncation() -> None:
    elastic = Mock()
    elastic.field_caps.return_value = {
        "fields": {
            f"custom.field.{index}": {
                "keyword": {"searchable": True, "aggregatable": True}
            }
            for index in range(5)
        }
    }

    result = InvestigationTools(elastic, Settings()).discover_fields(
        DiscoverFieldsArgs(index="logs-*", max_fields=2)
    )

    assert result.data["total_fields"] == 5
    assert result.data["returned_fields"] == 2
    assert result.data["truncated"] is True
    assert result.data["columns"] == ["field", "type", "searchable", "aggregatable"]
    assert result.data["rows"] == [
        ["custom.field.0", "keyword", True, True],
        ["custom.field.1", "keyword", True, True],
    ]
    assert elastic.field_caps.call_args.kwargs["fields"] == ["*"]
    assert elastic.field_caps.call_args.kwargs["request_timeout"] == 10


def test_field_discovery_preserves_conflicting_types_and_supports_custom_patterns() -> None:
    elastic = Mock()
    elastic.field_caps.return_value = {
        "fields": {
            "@timestamp": {"date": {"searchable": True, "aggregatable": True}},
            "custom.value": {
                "keyword": {"searchable": True, "aggregatable": True},
                "long": {"searchable": True, "aggregatable": False},
            },
            "_ignored": {"keyword": {"searchable": True, "aggregatable": False}},
        }
    }
    tools = InvestigationTools(elastic, Settings())

    result = tools.discover_fields(
        DiscoverFieldsArgs(index="logs-*", field_pattern="custom.*")
    )

    assert result.data["rows"] == [
        ["custom.value", "keyword", True, True],
        ["custom.value", "long", True, False],
    ]
    assert tools.discover_fields(
        DiscoverFieldsArgs(index="logs-*", field_pattern="_*")
    ).data["rows"][0][0] == "_ignored"


def test_field_discovery_caches_overlapping_requests_and_supports_continuation() -> None:
    elastic = Mock()
    elastic.field_caps.return_value = {
        "fields": {
            "http.request.method": {"keyword": {"searchable": True, "aggregatable": True}},
            "http.response.status_code": {"long": {"searchable": True, "aggregatable": True}},
            "process.name": {"keyword": {"searchable": True, "aggregatable": True}},
        }
    }
    tools = InvestigationTools(elastic, Settings())

    first = tools.discover_fields(
        DiscoverFieldsArgs(index="logs-*", field_prefix="http.", max_fields=1)
    )
    second = tools.discover_fields(
        DiscoverFieldsArgs(
            index="logs-*",
            field_prefix="http.",
            after_field=first.data["next_after_field"],
        )
    )

    assert first.data["returned_fields"] == 1
    assert second.data["rows"] == [
        ["http.response.status_code", "long", True, True]
    ]
    elastic.field_caps.assert_called_once()


def test_field_discovery_reports_byte_truncation() -> None:
    elastic = Mock()
    elastic.field_caps.return_value = {
        "fields": {
            f"custom.{index:03d}." + ("x" * 60): {
                "keyword": {"searchable": True, "aggregatable": True}
            }
            for index in range(20)
        }
    }
    result = InvestigationTools(elastic, Settings(max_tool_result_bytes=1001)).discover_fields(
        DiscoverFieldsArgs(index="logs-*", max_fields=20)
    )

    import json
    assert result.data["truncated"] is True
    assert result.data["omitted_field_count"] > 0
    assert len(json.dumps(result.data, separators=(",", ":"))) <= 1001


def test_field_discovery_allows_configured_patterns_and_matching_concrete_indices() -> None:
    elastic = Mock()
    elastic.field_caps.return_value = {"fields": {}}
    tools = InvestigationTools(elastic, Settings())

    for index in ("logs-*", "logs-endpoint.events-2026.11.15", ".alerts-security.alerts-default"):
        result = tools.discover_fields(DiscoverFieldsArgs(index=index))
        assert result.ok is True

    assert elastic.field_caps.call_count == 3


def test_field_discovery_rejects_unauthorized_index_with_safe_allowlist() -> None:
    elastic = Mock()
    tools = InvestigationTools(elastic, Settings())

    result = tools.discover_fields(DiscoverFieldsArgs(index="metrics-system-2026.11.15"))

    assert result.ok is False
    assert "metrics-system-2026.11.15" in (result.error or "")
    assert "logs-*" in (result.error or "")
    assert ".alerts-security.alerts-default" in (result.error or "")
    elastic.field_caps.assert_not_called()
