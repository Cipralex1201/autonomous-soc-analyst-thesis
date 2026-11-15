from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from src.config import Settings
from src.schemas import HttpStatisticsArgs, RelatedAlertsArgs, SourceActivityArgs
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
    assert elastic.search.call_args.kwargs["sort"] == [{"@timestamp": "asc"}, {"_id": "asc"}]


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
        "detection_evidence": {"event_count": 4},
    }
    assert "investigation guide" not in str(result.data)
    assert "full detection query" not in str(result.data)
