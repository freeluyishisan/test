from dataclasses import dataclass, field
from datetime import datetime

from backend.app.config import settings
from backend.app.models.rule_model import WeatherSnapshot


@dataclass(frozen=True)
class TradeFilterResult:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


def weather_data_age_seconds(snapshot: WeatherSnapshot) -> float:
    now = datetime.now(snapshot.observed_at.tzinfo)
    return max(0.0, (now - snapshot.observed_at).total_seconds())


def filter_weather_snapshot(snapshot: WeatherSnapshot) -> TradeFilterResult:
    reasons: list[str] = []

    if "HKO" not in snapshot.station and "HK Observatory" not in snapshot.station:
        reasons.append("STATION_MISMATCH")

    if weather_data_age_seconds(snapshot) > settings.max_data_staleness_seconds:
        reasons.append("STALE_WEATHER_DATA")

    if snapshot.current_temp_c is None or snapshot.today_high_c is None:
        reasons.append("MISSING_CORE_TEMPERATURE")

    if snapshot.radar_status == "unknown" or snapshot.satellite_status == "unknown":
        # Warning-level for now. It becomes hard block near decision windows later.
        reasons.append("RADAR_OR_SATELLITE_UNKNOWN")

    hard_block = [
        reason
        for reason in reasons
        if reason
        in {
            "STATION_MISMATCH",
            "STALE_WEATHER_DATA",
            "MISSING_CORE_TEMPERATURE",
        }
    ]

    return TradeFilterResult(allowed=not hard_block, reasons=reasons)


def filter_entry_price(yes_price: float, side: str, max_entry_price: float = 0.75) -> TradeFilterResult:
    if side.upper() in {"BUY_YES", "BUY_YES_CANDIDATE", "SMALL_BUY_YES_CANDIDATE"}:
        if yes_price > max_entry_price:
            return TradeFilterResult(False, ["ENTRY_PRICE_TOO_HIGH"])
    return TradeFilterResult(True, [])


def filter_edge(edge: float, min_edge: float | None = None) -> TradeFilterResult:
    min_edge = settings.min_edge_to_trade if min_edge is None else min_edge
    if abs(edge) < min_edge:
        return TradeFilterResult(False, ["EDGE_TOO_SMALL"])
    return TradeFilterResult(True, [])
