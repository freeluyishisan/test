from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

from backend.app.collectors.hko_parsers import HkoStationReading, parse_hko_rhrread

RHRREAD_URL = "https://data.weather.gov.hk/weatherAPI/opendata/weather.php?dataType=rhrread&lang=en"


@dataclass(frozen=True)
class HkoRhrreadRaw:
    fetched_at: datetime
    url: str
    payload: dict


async def fetch_hko_rhrread() -> HkoRhrreadRaw:
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(RHRREAD_URL)
        response.raise_for_status()
        return HkoRhrreadRaw(
            fetched_at=datetime.now(ZoneInfo("Asia/Hong_Kong")),
            url=RHRREAD_URL,
            payload=response.json(),
        )


async def get_hko_rhrread_reading() -> HkoStationReading:
    raw = await fetch_hko_rhrread()
    return parse_hko_rhrread(raw.payload, raw.fetched_at)
