from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

from backend.app.config import settings


@dataclass(frozen=True)
class HkoTextonlyRaw:
    fetched_at: datetime
    url: str
    body: str


async def fetch_hko_textonly() -> HkoTextonlyRaw:
    """Fetch HKO textonly readings page.

    Parser will be added after comparing live text_readings_e/c with hko.csv and AWS1.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(settings.hko_textonly_url)
        response.raise_for_status()
        return HkoTextonlyRaw(
            fetched_at=datetime.now(ZoneInfo("Asia/Hong_Kong")),
            url=settings.hko_textonly_url,
            body=response.text,
        )
