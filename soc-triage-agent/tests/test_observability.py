import logging

import pytest

from src.observability import inspect_request


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
