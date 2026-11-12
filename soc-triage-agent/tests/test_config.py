import pytest
from pydantic import ValidationError

from src.config import Settings


def test_settings_reject_invalid_url() -> None:
    with pytest.raises(ValidationError):
        Settings(elastic_url="localhost:9200")


def test_settings_reject_large_query_window() -> None:
    with pytest.raises(ValidationError):
        Settings(max_query_window_minutes=1441)
