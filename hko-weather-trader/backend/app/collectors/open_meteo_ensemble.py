from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx


@dataclass(frozen=True)
class EnsembleRequest:
    latitude: float
    longitude: float
    timezone: str
    forecast_hours: int = 24
    models: str = "gfs025"


@dataclass(frozen=True)
class EnsembleRaw:
    fetched_at: datetime
    request: EnsembleRequest
    payload: dict


async def fetch_open_meteo_ensemble(request: EnsembleRequest) -> EnsembleRaw:
    """Fetch Open-Meteo ensemble as background model data.

    This is not a settlement source. It should only be used as a forecast background
    and must be calibrated against the official station observations.
    """
    url = "https://ensemble-api.open-meteo.com/v1/ensemble"
    params = {
        "latitude": request.latitude,
        "longitude": request.longitude,
        "models": request.models,
        "hourly": ",".join(
            [
                "temperature_2m",
                "relative_humidity_2m",
                "cloud_cover",
                "wind_speed_10m",
                "wind_direction_10m",
                "shortwave_radiation",
                "direct_radiation",
            ]
        ),
        "timezone": request.timezone,
        "forecast_hours": request.forecast_hours,
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return EnsembleRaw(
            fetched_at=datetime.now(ZoneInfo("UTC")),
            request=request,
            payload=response.json(),
        )
