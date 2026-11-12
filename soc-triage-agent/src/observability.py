"""Sanitized request inspection and structured investigation logging."""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping
from typing import Any


_SECRET_KEY = re.compile(r"(api[_-]?key|authorization|cookie|password|token|secret)", re.I)


def sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: "[REDACTED]" if _SECRET_KEY.search(str(key)) else sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", value)
    return value


def inspect_request(payload: Mapping[str, Any], mode: str, logger: logging.Logger) -> None:
    sanitized = sanitize(payload)
    rendered = json.dumps(sanitized, default=str, indent=2)
    if mode == "log":
        logger.info("LLM request:\n%s", rendered)
    elif mode == "pause":
        if not sys.stdin.isatty():
            raise RuntimeError("PROMPT_INSPECTION_MODE=pause requires an interactive terminal")
        print(rendered)
        if input("Send this request to OpenAI? [y/N] ").strip().lower() not in {"y", "yes"}:
            raise RuntimeError("LLM request rejected by operator")
