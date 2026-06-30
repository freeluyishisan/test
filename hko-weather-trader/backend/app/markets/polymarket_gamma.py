from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx

GAMMA_BASE = "https://gamma-api.polymarket.com"


@dataclass(frozen=True)
class PolymarketEvent:
    slug: str
    title: str | None
    raw: dict
    fetched_at: datetime


async def fetch_event_by_slug(slug: str) -> PolymarketEvent | None:
    url = f"{GAMMA_BASE}/events"
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, params={"slug": slug})
        response.raise_for_status()
        payload = response.json()

    if isinstance(payload, list):
        event = payload[0] if payload else None
    elif isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            event = data[0] if data else None
        else:
            event = payload
    else:
        event = None

    if not isinstance(event, dict):
        return None

    return PolymarketEvent(
        slug=slug,
        title=event.get("title") or event.get("question"),
        raw=event,
        fetched_at=datetime.now(ZoneInfo("UTC")),
    )


async def fetch_active_events(limit: int = 100) -> list[PolymarketEvent]:
    url = f"{GAMMA_BASE}/events"
    params = {
        "active": "true",
        "closed": "false",
        "order": "volume_24hr",
        "ascending": "false",
        "limit": limit,
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        payload = response.json()

    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        items = payload["data"]
    elif isinstance(payload, list):
        items = payload
    else:
        items = []

    fetched_at = datetime.now(ZoneInfo("UTC"))
    events = []
    for item in items:
        if not isinstance(item, dict):
            continue
        slug = item.get("slug")
        if not slug:
            continue
        events.append(
            PolymarketEvent(
                slug=slug,
                title=item.get("title") or item.get("question"),
                raw=item,
                fetched_at=fetched_at,
            )
        )
    return events


def find_temperature_events(events: list[PolymarketEvent], keywords: list[str]) -> list[PolymarketEvent]:
    lowered = [kw.lower() for kw in keywords]
    matches = []
    for event in events:
        haystack = f"{event.slug} {event.title or ''}".lower()
        if all(keyword in haystack for keyword in lowered):
            matches.append(event)
    return matches


def extract_markets(event: PolymarketEvent) -> list[dict]:
    markets = event.raw.get("markets")
    if isinstance(markets, list):
        return [m for m in markets if isinstance(m, dict)]
    return []
