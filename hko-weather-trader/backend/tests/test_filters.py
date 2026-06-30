from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from backend.app.models.rule_model import WeatherSnapshot
from backend.app.strategy.filters import filter_edge, filter_entry_price, filter_weather_snapshot


def test_filter_edge_small() -> None:
    result = filter_edge(0.03, min_edge=0.08)
    assert not result.allowed
    assert "EDGE_TOO_SMALL" in result.reasons


def test_filter_entry_price_too_high() -> None:
    result = filter_entry_price(0.82, "BUY_YES_CANDIDATE", max_entry_price=0.75)
    assert not result.allowed
    assert "ENTRY_PRICE_TOO_HIGH" in result.reasons


def test_filter_weather_stale() -> None:
    tz = ZoneInfo("Asia/Hong_Kong")
    snapshot = WeatherSnapshot(
        market_key="hk_hko_daily_high",
        station="HKO / HK Observatory",
        observed_at=datetime.now(tz) - timedelta(minutes=10),
        current_temp_c=30.0,
        today_high_c=30.2,
    )
    result = filter_weather_snapshot(snapshot)
    assert not result.allowed
    assert "STALE_WEATHER_DATA" in result.reasons
