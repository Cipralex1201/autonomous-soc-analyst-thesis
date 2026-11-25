from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from src.schemas import ElasticsearchSearchArgs, RelatedAlertsArgs, TimeWindow


def test_related_alerts_requires_an_identity() -> None:
    with pytest.raises(ValidationError):
        RelatedAlertsArgs(
            start=datetime.now(timezone.utc),
            end=datetime.now(timezone.utc) + timedelta(minutes=1),
        )


def test_time_window_rejects_reversed_values() -> None:
    with pytest.raises(ValidationError):
        TimeWindow(
            start=datetime.now(timezone.utc),
            end=datetime.now(timezone.utc) - timedelta(minutes=1),
        )


def test_search_args_allow_zero_but_reject_unbounded_size_values() -> None:
    args = ElasticsearchSearchArgs(index="logs-*", query={"match_all": {}}, size=0)

    assert args.size == 0
    with pytest.raises(ValidationError):
        ElasticsearchSearchArgs(index="logs-*", query={"match_all": {}}, size=-1)
    with pytest.raises(ValidationError):
        ElasticsearchSearchArgs(index="logs-*", query={"match_all": {}}, size=1001)
