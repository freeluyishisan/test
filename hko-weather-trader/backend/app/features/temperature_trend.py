from dataclasses import replace
from datetime import datetime
from typing import Any

from backend.app.models.rule_model import WeatherSnapshot


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _closest_before(rows: list[dict[str, Any]], target_ts: datetime) -> dict[str, Any] | None:
    candidates = []
    for row in rows:
        try:
            observed_at = _parse_dt(row["observed_at"])
        except Exception:  # noqa: BLE001
            continue
        if observed_at <= target_ts:
            candidates.append((observed_at, row))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _slope_delta(snapshot: WeatherSnapshot, rows: list[dict[str, Any]], minutes: int) -> float | None:
    target = snapshot.observed_at.timestamp() - minutes * 60
    target_dt = datetime.fromtimestamp(target, tz=snapshot.observed_at.tzinfo)
    base = _closest_before(rows, target_dt)
    if not base:
        return None
    temp = base.get("current_temp_c")
    if temp is None:
        return None
    try:
        return round(snapshot.current_temp_c - float(temp), 2)
    except (TypeError, ValueError):
        return None


def attach_temperature_trends(
    snapshot: WeatherSnapshot,
    recent_rows: list[dict[str, Any]],
) -> WeatherSnapshot:
    """Attach 10/30/60 minute temperature deltas to a snapshot.

    Values are absolute delta °C over the window, not °C/hour.
    Example: recent_slope_30m=0.4 means current temp is 0.4°C above the closest
    reading at least 30 minutes ago.
    """
    return replace(
        snapshot,
        recent_slope_10m=_slope_delta(snapshot, recent_rows, 10),
        recent_slope_30m=_slope_delta(snapshot, recent_rows, 30),
        recent_slope_60m=_slope_delta(snapshot, recent_rows, 60),
    )
