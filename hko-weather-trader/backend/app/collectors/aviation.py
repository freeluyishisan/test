from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx


@dataclass(frozen=True)
class AviationReport:
    station: str
    report_type: str
    fetched_at: datetime
    raw: dict | list | str


async def fetch_metar(station_ids: list[str]) -> AviationReport:
    ids = ",".join(station_ids)
    url = "https://aviationweather.gov/api/data/metar"
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, params={"ids": ids, "format": "json"})
        response.raise_for_status()
        return AviationReport(
            station=ids,
            report_type="METAR",
            fetched_at=datetime.now(ZoneInfo("UTC")),
            raw=response.json(),
        )


async def fetch_taf(station_ids: list[str]) -> AviationReport:
    ids = ",".join(station_ids)
    url = "https://aviationweather.gov/api/data/taf"
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, params={"ids": ids, "format": "json"})
        response.raise_for_status()
        return AviationReport(
            station=ids,
            report_type="TAF",
            fetched_at=datetime.now(ZoneInfo("UTC")),
            raw=response.json(),
        )


def extract_metar_temperature_c(report: AviationReport, station_id: str) -> float | None:
    if not isinstance(report.raw, list):
        return None
    for item in report.raw:
        if not isinstance(item, dict):
            continue
        if str(item.get("icaoId", "")).upper() != station_id.upper():
            continue
        value = item.get("temp") or item.get("temp_c") or item.get("temperature")
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    return None
