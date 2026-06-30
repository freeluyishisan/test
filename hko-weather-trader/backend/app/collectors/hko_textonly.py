from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

from backend.app.config import settings
from backend.app.collectors.hko_parsers import (
    HkoStationReading,
    parse_hko_textonly,
    parse_textonly_king_park_radiation,
)


@dataclass(frozen=True)
class HkoTextonlyRaw:
    fetched_at: datetime
    url: str
    body: str


async def fetch_hko_textonly() -> HkoTextonlyRaw:
    """Fetch HKO textonly readings page."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(settings.hko_textonly_url)
        response.raise_for_status()
        return HkoTextonlyRaw(
            fetched_at=datetime.now(ZoneInfo("Asia/Hong_Kong")),
            url=settings.hko_textonly_url,
            body=response.text,
        )


async def get_hko_textonly_reading() -> HkoStationReading:
    raw = await fetch_hko_textonly()
    return parse_hko_textonly(raw.body, raw.fetched_at)


async def get_king_park_radiation_from_textonly() -> HkoStationReading | None:
    raw = await fetch_hko_textonly()
    return parse_textonly_king_park_radiation(raw.body, raw.fetched_at)
