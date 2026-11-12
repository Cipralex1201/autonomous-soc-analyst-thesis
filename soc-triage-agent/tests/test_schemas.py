from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from src.schemas import RelatedAlertsArgs, TimeWindow


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
