import asyncio
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from backend.app.collectors.hko_csv import get_hko_csv_reading
from backend.app.collectors.hko_parsers import HkoStationReading
from backend.app.collectors.hko_rhrread import get_hko_rhrread_reading
from backend.app.collectors.hko_textonly import (
    get_hko_textonly_reading,
    get_king_park_radiation_from_textonly,
)
from backend.app.models.rule_model import WeatherSnapshot

HK_TZ = ZoneInfo("Asia/Hong_Kong")


@dataclass(frozen=True)
class HkoSourceBundle:
    textonly: HkoStationReading | None
    csv: HkoStationReading | None
    rhrread: HkoStationReading | None
    radiation: HkoStationReading | None
    errors: dict[str, str]


def _pick_first(*values: float | None) -> float | None:
    for value in values:
        if value is not None:
            return value
    return None


async def _safe_call(name: str, coro, errors: dict[str, str]):
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001 - collector errors should not kill the full snapshot
        errors[name] = f"{type(exc).__name__}: {exc}"
        return None


async def collect_hko_sources() -> HkoSourceBundle:
    errors: dict[str, str] = {}
    textonly, csv_reading, rhrread, radiation = await asyncio.gather(
        _safe_call("textonly", get_hko_textonly_reading(), errors),
        _safe_call("hko_csv", get_hko_csv_reading(), errors),
        _safe_call("rhrread", get_hko_rhrread_reading(), errors),
        _safe_call("radiation", get_king_park_radiation_from_textonly(), errors),
    )
    return HkoSourceBundle(
        textonly=textonly,
        csv=csv_reading,
        rhrread=rhrread,
        radiation=radiation,
        errors=errors,
    )


def build_hko_snapshot(bundle: HkoSourceBundle) -> WeatherSnapshot:
    """Merge HKO sources into the model snapshot.

    Priority:
    - current temp: textonly -> hko.csv -> rhrread
    - today high/low: textonly only for now
    - humidity: textonly -> rhrread
    - radiation: textonly King's Park row when present
    """
    textonly = bundle.textonly
    csv_reading = bundle.csv
    rhrread = bundle.rhrread
    radiation = bundle.radiation

    current_temp = _pick_first(
        textonly.current_temp_c if textonly else None,
        csv_reading.current_temp_c if csv_reading else None,
        rhrread.current_temp_c if rhrread else None,
    )
    today_high = _pick_first(
        textonly.today_high_c if textonly else None,
        current_temp,
    )
    humidity = _pick_first(
        textonly.humidity if textonly else None,
        rhrread.humidity if rhrread else None,
    )

    if current_temp is None or today_high is None:
        raise ValueError(f"cannot build HKO snapshot, missing temp/high; errors={bundle.errors}")

    observed_at = (
        textonly.observed_at
        if textonly and textonly.observed_at
        else rhrread.observed_at
        if rhrread and rhrread.observed_at
        else datetime.now(HK_TZ)
    )

    return WeatherSnapshot(
        market_key="hk_hko_daily_high",
        station="HKO / HK Observatory",
        observed_at=observed_at,
        current_temp_c=current_temp,
        today_high_c=today_high,
        humidity=humidity,
        radiation_global=radiation.global_solar_wm2 if radiation else None,
        radiation_direct=radiation.direct_solar_wm2 if radiation else None,
        radar_status="unknown",
        satellite_status="unknown",
    )


async def get_hko_snapshot() -> tuple[WeatherSnapshot, HkoSourceBundle]:
    bundle = await collect_hko_sources()
    snapshot = build_hko_snapshot(bundle)
    return snapshot, bundle
