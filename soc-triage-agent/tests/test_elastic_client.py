from unittest.mock import Mock

from src.config import Settings
from src.elastic_client import ElasticClient


def test_alert_normalization_keeps_optional_http_fields_optional() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-1",
        {"kibana.alert.rule.name": "Windows rule", "source.ip": "192.0.2.10"},
    )
    assert alert.alert_id == "alert-1"
    assert alert.rule_name == "Windows rule"
    assert alert.source_ip == "192.0.2.10"


def test_search_rejects_unconfigured_index() -> None:
    client = ElasticClient(Settings(), client=Mock())
    try:
        client.search(index="arbitrary-*", query={"match_all": {}}, size=1)
    except ValueError as exc:
        assert "not configured" in str(exc)
    else:
        raise AssertionError("unconfigured index was accepted")


def test_read_access_uses_alert_index_search_without_ping() -> None:
    client_api = Mock()
    client = ElasticClient(Settings(), client=client_api)

    client.check_read_access()

    client_api.search.assert_called_once_with(
        index=".alerts-security.alerts-default",
        query={"match_all": {}},
        size=0,
        track_total_hits=False,
    )
    client_api.ping.assert_not_called()
