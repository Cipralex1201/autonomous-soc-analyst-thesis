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


def test_alert_normalization_extracts_dataset_and_originating_index() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-1",
        {
            "event": {"dataset": "endpoint.events"},
            "data_stream": {"dataset": "endpoint.events"},
        },
        "logs-endpoint.events-2026.11.17",
    )

    assert alert.telemetry_datasets == ["endpoint.events"]
    assert alert.originating_indices == ["logs-endpoint.events-2026.11.17"]
    assert alert.telemetry_provenance == "known"


def test_alert_normalization_marks_conflicting_dataset_provenance_ambiguous() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-1",
        {"event.dataset": "http", "data_stream.dataset": "nginx.access"},
    )

    assert alert.telemetry_datasets == ["http", "nginx.access"]
    assert alert.telemetry_provenance == "ambiguous"


def test_alert_normalization_marks_missing_provenance() -> None:
    alert = ElasticClient.normalize_alert("alert-1", {})

    assert alert.telemetry_provenance == "missing"


def test_windows_process_alert_preserves_security_relevant_evidence() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-windows",
        {
            "event": {"dataset": "windows.sysmon_operational", "category": ["process"], "kind": "signal"},
            "host": {
                "name": "cloud-29250",
                "id": "98584165-a96a-486d-9e0b-41f0c992a9db",
            },
            "user": {"name": "cloud", "id": "S-1-5-18"},
            "process": {
                "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command Get-Process',
                "entity_id": "{98584165-ABE6-6AFB-0909-000000003700}",
                "pid": 9492,
                "hash": {"sha256": "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"},
                "parent": {
                    "name": "wscript.exe",
                    "command_line": r'"C:\WINDOWS\system32\wscript.exe" C:\Users\cloud\AppData\Local\Temp\soc-lab-test.js',
                },
            },
            "kibana": {"alert": {"rule": {"parameters": {"note": "large investigation guide"}}}},
        },
        "logs-windows.sysmon_operational-*",
    )

    evidence = alert.detection_evidence
    assert evidence["process.executable"].endswith(r"powershell.exe")
    assert evidence["process.command_line"].endswith("Get-Process")
    assert evidence["process.entity_id"] == "{98584165-ABE6-6AFB-0909-000000003700}"
    assert evidence["process.pid"] == 9492
    assert evidence["process.parent.command_line"].startswith('"C:\\WINDOWS')
    assert evidence["process.hash.sha256"] == "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"
    assert evidence["host.name"] == "cloud-29250"
    assert evidence["host.id"] == "98584165-a96a-486d-9e0b-41f0c992a9db"
    assert evidence["user.name"] == "cloud"
    assert evidence["user.id"] == "S-1-5-18"
    assert "kibana" not in str(evidence)
    assert "investigation guide" not in str(evidence)


def test_generic_alert_normalization_supports_authentication_file_dns_and_http() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-generic",
        {
            "event": {"category": ["authentication", "file", "network"], "dataset": "generic.logs"},
            "user": {"name": "alice", "id": "u-123"},
            "authentication": {"outcome": "failure"},
            "file": {"path": r"C:\Temp\payload.exe", "hash": {"sha256": "abc123"}},
            "dns": {"question": {"name": "example.test"}, "resolved_ip": ["192.0.2.44"]},
            "network": {"transport": "tcp", "direction": "egress"},
            "source": {"ip": "192.0.2.10"},
            "destination": {"ip": "198.51.100.20", "port": 443},
            "http": {"request": {"method": "POST"}, "response": {"status_code": 404}},
            "url": {"path": "/upload", "domain": "example.test"},
            "Esql": {"event_count": 12, "detected_entities": ["entity-a"]},
        },
    )

    evidence = alert.detection_evidence
    assert evidence["authentication.outcome"] == "failure"
    assert evidence["file.path"] == r"C:\Temp\payload.exe"
    assert evidence["dns.question.name"] == "example.test"
    assert evidence["network.transport"] == "tcp"
    assert evidence["http.request.method"] == "POST"
    assert evidence["url.path"] == "/upload"
    assert evidence["event_count"] == 12
    assert evidence["custom"]["esql"]["detected_entities"]["representative"] == ["entity-a"]


def test_alert_evidence_marks_field_and_text_omissions() -> None:
    alert = ElasticClient.normalize_alert(
        "alert-long",
        {
            "process": {
                "command_line": "x" * 500,
                "executable": "C:\\Temp\\payload.exe",
            },
            "custom": {
                f"field_{index}": index
                for index in range(30)
            },
        },
        max_text_length=100,
        max_fields=1,
    )

    evidence = alert.detection_evidence
    assert "[omitted 400 characters]" in evidence["process.command_line"]
    assert "_omitted_fields" in evidence

def test_search_rejects_unconfigured_index() -> None:
    client = ElasticClient(Settings(), client=Mock())
    try:
        client.search(index="arbitrary-*", query={"match_all": {}}, size=1)
    except ValueError as exc:
        assert "arbitrary-*" in str(exc)
        assert "logs-*" in str(exc)
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


def test_alert_search_uses_supported_shard_sort_instead_of_id_sort() -> None:
    client_api = Mock()
    client_api.search.return_value = {"hits": {"hits": []}}
    client = ElasticClient(Settings(), client=client_api)

    client.search_alerts(query={"match_all": {}}, size=10)

    assert client_api.search.call_args.kwargs["sort"] == [
        {"kibana.alert.original_time": "asc"},
        {"_shard_doc": "asc"},
    ]


def test_search_passes_source_filter_and_timeout_to_elasticsearch() -> None:
    client_api = Mock()
    client_api.search.return_value = {"hits": {"hits": []}}
    client = ElasticClient(Settings(), client=client_api)

    client.search(
        index="logs-*",
        query={"match_all": {}},
        size=10,
        source=["@timestamp", "process.name"],
        sort=[{"@timestamp": "asc"}],
        timeout="10s",
    )

    request = client_api.search.call_args.kwargs
    assert request["_source"] == ["@timestamp", "process.name"]
    assert request["sort"] == [{"@timestamp": "asc"}]
    assert request["timeout"] == "10s"


def test_field_caps_uses_client_request_timeout_not_field_caps_keyword() -> None:
    client_api = Mock()
    request_client = Mock()
    request_client.field_caps.return_value = {"fields": {}}
    client_api.options.return_value = request_client
    client = ElasticClient(Settings(), client=client_api)

    result = client.field_caps(
        index="logs-*",
        fields=["*"],
        request_timeout=10,
    )

    assert result == {"fields": {}}
    client_api.options.assert_called_once_with(request_timeout=10)
    request_client.field_caps.assert_called_once_with(index="logs-*", fields=["*"])
    client_api.field_caps.assert_not_called()
