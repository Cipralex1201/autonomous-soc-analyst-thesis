from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from src.config import Settings
from src.schemas import HttpStatisticsArgs
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
