from unittest.mock import Mock

from src.config import Settings
from src.elastic_client import ElasticClient


def test_alert_normalization_keeps_optional_http_fields_optional() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-1",
        {"kibana": {"alert": {"rule": {"name": "Windows rule"}}}},
    )
    assert alert.alert_id == "alert-1"
    assert alert.rule_name == "Windows rule"
    assert alert.source_ip is None


def test_search_rejects_unconfigured_index() -> None:
    client = ElasticClient(Settings(), client=Mock())
    try:
        client.search(index="arbitrary-*", query={"match_all": {}}, size=1)
    except ValueError as exc:
        assert "not configured" in str(exc)
    else:
        raise AssertionError("unconfigured index was accepted")
