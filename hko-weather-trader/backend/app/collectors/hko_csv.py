from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

from backend.app.config import settings


@dataclass(frozen=True)
class HkoCsvRaw:
    fetched_at: datetime
    url: str
    csv_text: str


async def fetch_hko_csv() -> HkoCsvRaw:
    """Fetch HKO awsgis/hko.csv raw content.

    Next step: parse the HK Observatory row and normalize into WeatherSnapshot.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(settings.hko_csv_url)
        response.raise_for_status()
        return HkoCsvRaw(
            fetched_at=datetime.now(ZoneInfo("Asia/Hong_Kong")),
            url=settings.hko_csv_url,
            csv_text=response.text,
        )
