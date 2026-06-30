import asyncio
from datetime import datetime
from zoneinfo import ZoneInfo

from backend.app.collectors.hko_snapshot import get_hko_snapshot
from backend.app.models.rule_model import WeatherSnapshot, forecast
from backend.app.strategy.edge import decide_yes_no


def demo_snapshot() -> WeatherSnapshot:
    now = datetime.now(ZoneInfo("Asia/Hong_Kong"))
    return WeatherSnapshot(
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


async def load_snapshot() -> tuple[WeatherSnapshot, dict[str, str]]:
    try:
        snapshot, bundle = await get_hko_snapshot()
        return snapshot, bundle.errors
    except Exception as exc:  # noqa: BLE001 - CLI should still show model output
        return demo_snapshot(), {"fallback_demo": f"{type(exc).__name__}: {exc}"}


def print_snapshot(snapshot: WeatherSnapshot, source_errors: dict[str, str]) -> None:
    print("=== HKO 观测快照 ===")
    print(f"站点：{snapshot.station}")
    print(f"观测时间：{snapshot.observed_at.isoformat()}")
    print(f"当前温度：{snapshot.current_temp_c:.1f}°C")
    print(f"今日最高：{snapshot.today_high_c:.1f}°C")
    if snapshot.humidity is not None:
        print(f"湿度：{snapshot.humidity:.0f}%")
    if snapshot.radiation_global is not None:
        print(f"King's Park 全球辐射：{snapshot.radiation_global:.1f} W/m²")
    if source_errors:
        print("源降级：")
        for name, error in source_errors.items():
            print(f"  - {name}: {error}")
    print()


def print_forecast(snapshot: WeatherSnapshot) -> None:
    result = forecast(snapshot)
    print("=== 预测与盘口判断 ===")
    print(result.summary)
    print()

    # Demo market prices. Replace with Polymarket Gamma/CLOB prices in V0.4.
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


def main() -> None:
    snapshot, source_errors = asyncio.run(load_snapshot())
    print_snapshot(snapshot, source_errors)
    print_forecast(snapshot)


if __name__ == "__main__":
    main()
