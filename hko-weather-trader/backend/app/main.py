from fastapi import FastAPI

from backend.app.markets.registry import EAST8_MARKETS

app = FastAPI(title="East-8 Weather Trader", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/markets")
def markets() -> list[dict]:
    return [market.__dict__ for market in EAST8_MARKETS.values()]
