from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class WeatherSnapshot:
    market_key: str
    station: str
    observed_at: datetime
    current_temp_c: float
    today_high_c: float
    humidity: float | None = None
    wind_dir_deg: float | None = None
    wind_speed_ms: float | None = None
    radiation_global: float | None = None
    radiation_direct: float | None = None
    radar_status: str | None = None
    satellite_status: str | None = None
    recent_slope_10m: float | None = None
    recent_slope_30m: float | None = None
    recent_slope_60m: float | None = None


@dataclass(frozen=True)
class ThresholdProbability:
    threshold_c: float
    yes_probability: float
    reason: str


@dataclass(frozen=True)
class ForecastResult:
    market_key: str
    station: str
    generated_at: datetime
    window_high_forecast_c: float
    daily_high_low_c: float
    daily_high_high_c: float
    threshold_probabilities: list[ThresholdProbability] = field(default_factory=list)
    summary: str = ""


def _clamp(value: float, low: float = 0.02, high: float = 0.98) -> float:
    return max(low, min(high, value))


def _time_weight(hour: int, minute: int) -> float:
    current = hour + minute / 60
    if 11 <= current < 12.5:
        return 0.55
    if 12.5 <= current < 13.5:
        return 0.7
    if 13.5 <= current <= 15.25:
        return 1.0
    if 15.25 < current <= 16.0:
        return 0.45
    if current > 16.0:
        return 0.18
    return 0.35


def estimate_threshold_probability(snapshot: WeatherSnapshot, threshold_c: float) -> ThresholdProbability:
    """First conservative HKO-style rule model.

    This is intentionally simple. It must be calibrated with paper trading records later.
    """
    if snapshot.today_high_c >= threshold_c:
        return ThresholdProbability(
            threshold_c=threshold_c,
            yes_probability=0.98,
            reason="今日已录得最高温已经达到阈值，YES 基本命中。",
        )

    distance = threshold_c - snapshot.today_high_c
    current_distance = threshold_c - snapshot.current_temp_c
    tw = _time_weight(snapshot.observed_at.hour, snapshot.observed_at.minute)

    slope_bonus = 0.0
    if snapshot.recent_slope_30m is not None:
        if snapshot.recent_slope_30m >= 0.4:
            slope_bonus += 0.18
        elif snapshot.recent_slope_30m >= 0.2:
            slope_bonus += 0.10
        elif snapshot.recent_slope_30m <= -0.3:
            slope_bonus -= 0.18

    radiation_bonus = 0.0
    if snapshot.radiation_global is not None:
        if snapshot.radiation_global >= 700:
            radiation_bonus += 0.14
        elif snapshot.radiation_global >= 500:
            radiation_bonus += 0.08
        elif snapshot.radiation_global < 250:
            radiation_bonus -= 0.16

    rain_penalty = 0.0
    if snapshot.radar_status in {"rain_near_station", "heavy_rain_near_station", "thunderstorm_near_station"}:
        rain_penalty -= 0.25

    cloud_penalty = 0.0
    if snapshot.satellite_status in {"thick_cloud", "deep_cloud"}:
        cloud_penalty -= 0.15
    elif snapshot.satellite_status in {"thin_cloud", "cloud_gap"}:
        cloud_penalty += 0.05

    # Base probability from distance to threshold.
    if distance <= 0.2:
        base = 0.72
    elif distance <= 0.5:
        base = 0.55
    elif distance <= 0.8:
        base = 0.36
    elif distance <= 1.2:
        base = 0.20
    else:
        base = 0.08

    # Current temperature matters more than already-recorded high if still rising.
    if current_distance <= 0.3:
        base += 0.10
    elif current_distance >= 1.0:
        base -= 0.08

    probability = _clamp(base * tw + slope_bonus + radiation_bonus + rain_penalty + cloud_penalty)

    reason = (
        f"距阈值 {distance:.1f}°C，时段权重 {tw:.2f}，"
        f"升温修正 {slope_bonus:+.2f}，辐射修正 {radiation_bonus:+.2f}，"
        f"雨区修正 {rain_penalty:+.2f}，云量修正 {cloud_penalty:+.2f}。"
    )
    return ThresholdProbability(threshold_c=threshold_c, yes_probability=probability, reason=reason)


def forecast(snapshot: WeatherSnapshot, thresholds: list[float] | None = None) -> ForecastResult:
    thresholds = thresholds or [30.0, 31.0, 32.0, 33.0]

    slope = snapshot.recent_slope_60m or snapshot.recent_slope_30m or 0.0
    window_high = max(snapshot.today_high_c, snapshot.current_temp_c + max(0.0, slope) * 0.7)

    if snapshot.radiation_global and snapshot.radiation_global >= 600:
        window_high += 0.2
    if snapshot.radar_status in {"rain_near_station", "heavy_rain_near_station"}:
        window_high -= 0.3

    window_high = round(window_high, 1)
    daily_low = round(max(snapshot.today_high_c, window_high - 0.2), 1)
    daily_high = round(max(daily_low, window_high + 0.3), 1)

    probs = [estimate_threshold_probability(snapshot, t) for t in thresholds]

    summary = (
        f"{snapshot.station} 当前 {snapshot.current_temp_c:.1f}°C，今日最高 {snapshot.today_high_c:.1f}°C，"
        f"未来 60 分钟高点估计 {window_high:.1f}°C，全天主区间 {daily_low:.1f}–{daily_high:.1f}°C。"
    )

    return ForecastResult(
        market_key=snapshot.market_key,
        station=snapshot.station,
        generated_at=datetime.now(snapshot.observed_at.tzinfo),
        window_high_forecast_c=window_high,
        daily_high_low_c=daily_low,
        daily_high_high_c=daily_high,
        threshold_probabilities=probs,
        summary=summary,
    )
