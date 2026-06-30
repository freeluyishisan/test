from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from backend.app.features.temperature_trend import attach_temperature_trends
from backend.app.models.rule_model import WeatherSnapshot


def test_attach_temperature_trends() -> None:
    tz = ZoneInfo("Asia/Hong_Kong")
    now = datetime(2026, 6, 30, 14, 0, tzinfo=tz)
    snapshot = WeatherSnapshot(
        market_key="hk_hko_daily_high",
        station="HKO / HK Observatory",
        observed_at=now,
        current_temp_c=31.0,
        today_high_c=31.0,
    )
    rows = [
        {
            "observed_at": (now - timedelta(minutes=65)).isoformat(),
            "current_temp_c": 30.0,
        },
        {
            "observed_at": (now - timedelta(minutes=35)).isoformat(),
            "current_temp_c": 30.5,
        },
        {
            "observed_at": (now - timedelta(minutes=12)).isoformat(),
            "current_temp_c": 30.8,
        },
    ]
    enriched = attach_temperature_trends(snapshot, rows)
    assert enriched.recent_slope_10m == 0.2
    assert enriched.recent_slope_30m == 0.5
    assert enriched.recent_slope_60m == 1.0
