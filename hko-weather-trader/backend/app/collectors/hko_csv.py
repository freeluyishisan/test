from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

from backend.app.config import settings
from backend.app.collectors.hko_parsers import HkoStationReading, parse_hko_csv


@dataclass(frozen=True)
class HkoCsvRaw:
    fetched_at: datetime
    url: str
    csv_text: str


async def fetch_hko_csv() -> HkoCsvRaw:
    """Fetch HKO awsgis/hko.csv raw content."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(settings.hko_csv_url)
        response.raise_for_status()
        return HkoCsvRaw(
            fetched_at=datetime.now(ZoneInfo("Asia/Hong_Kong")),
            url=settings.hko_csv_url,
            csv_text=response.text,
        )


async def get_hko_csv_reading() -> HkoStationReading:
    raw = await fetch_hko_csv()
    return parse_hko_csv(raw.csv_text, raw.fetched_at)
