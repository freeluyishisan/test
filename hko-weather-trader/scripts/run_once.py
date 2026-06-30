from datetime import datetime
from zoneinfo import ZoneInfo

from backend.app.models.rule_model import WeatherSnapshot, forecast
from backend.app.strategy.edge import decide_yes_no


def main() -> None:
    """Demo runner with placeholder HKO snapshot.

    Next step: replace this with real HKO collectors.
    """
    now = datetime.now(ZoneInfo("Asia/Hong_Kong"))
    snapshot = WeatherSnapshot(
        market_key="hk_hko_daily_high",
        station="HKO / HK Observatory",
        observed_at=now,
        current_temp_c=30.6,
        today_high_c=30.8,
        humidity=72,
        wind_dir_deg=180,
        wind_speed_ms=3.2,
        radiation_global=620,
        radiation_direct=180,
        radar_status="clear_near_station",
        satellite_status="thin_cloud",
        recent_slope_10m=0.1,
        recent_slope_30m=0.3,
        recent_slope_60m=0.5,
    )

    result = forecast(snapshot)
    print(result.summary)
    print()

    # Demo market prices. Replace with Polymarket CLOB prices later.
    demo_prices = {30.0: 0.96, 31.0: 0.52, 32.0: 0.18, 33.0: 0.05}

    for prob in result.threshold_probabilities:
        price = demo_prices.get(prob.threshold_c, 0.5)
        decision = decide_yes_no(
            model_yes_probability=prob.yes_probability,
            yes_market_price=price,
        )
        print(
            f"{prob.threshold_c:.0f}°C YES | "
            f"模型 {prob.yes_probability:.1%} | 盘口 {price:.1%} | "
            f"edge {decision.edge:+.1%} | {decision.action} | "
            f"size={decision.suggested_size_usdc} USDC"
        )
        print(f"  理由：{prob.reason}")


if __name__ == "__main__":
    main()
