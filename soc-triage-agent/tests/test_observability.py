import logging
from unittest.mock import Mock

import pytest

from src.observability import InvestigationRecorder, inspect_request


def test_pause_mode_requires_interactive_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.observability.sys.stdin.isatty", lambda: False)
    with pytest.raises(RuntimeError, match="interactive"):
        inspect_request({"input": "test"}, "pause", logging.getLogger("test"))


def test_pause_mode_prints_exact_payload(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("src.observability.sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(RuntimeError, match="rejected"):
        inspect_request({"schema": {"additionalProperties": False}}, "pause", logging.getLogger("test"))
    assert '"additionalProperties": false' in capsys.readouterr().out


def test_investigation_recorder_writes_ordered_jsonl(tmp_path) -> None:
    recorder = InvestigationRecorder(
        investigation_id="investigation-1",
        alert_id="alert-1",
        directory=tmp_path,
        elastic_enabled=False,
    )
    recorder.record("investigation.started", model="test-model")
    recorder.record("investigation.completed", status="completed")

    lines = recorder.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    import json
    events = [json.loads(line) for line in lines]
    assert [event["sequence"] for event in events] == [1, 2]
    assert all(event["investigation_id"] == "investigation-1" for event in events)
    assert all(event["alert_id"] == "alert-1" for event in events)


def test_investigation_recorder_is_elasticsearch_idempotent_on_replay(tmp_path) -> None:
    elastic = Mock()
    recorder = InvestigationRecorder(
        investigation_id="investigation-2",
        alert_id="alert-2",
        directory=tmp_path,
        elastic_client=elastic,
        elastic_enabled=True,
    )
    recorder.record("investigation.started")

    indexed, failed = recorder.replay()
    assert indexed == 1
    assert failed == 0
    elastic.index_trace_event.assert_called()
