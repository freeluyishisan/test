import asyncio
import sys

from backend.app.markets.polymarket_gamma import fetch_active_events, find_temperature_events


async def main() -> None:
    keywords = sys.argv[1:] or ["temperature"]
    events = await fetch_active_events(limit=200)
    matches = find_temperature_events(events, keywords)

    print(f"active_events={len(events)} matched={len(matches)} keywords={keywords}")
    for event in matches[:30]:
        print(f"- {event.slug} | {event.title}")


if __name__ == "__main__":
    asyncio.run(main())
