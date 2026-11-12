import logging

import pytest

from src.observability import inspect_request


def test_pause_mode_requires_interactive_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.observability.sys.stdin.isatty", lambda: False)
    with pytest.raises(RuntimeError, match="interactive"):
        inspect_request({"input": "test"}, "pause", logging.getLogger("test"))
