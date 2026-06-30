import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from backend.app.config import settings
from backend.app.models.rule_model import WeatherSnapshot


SCHEMA = """
CREATE TABLE IF NOT EXISTS weather_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    market_key TEXT NOT NULL,
    station TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    saved_at TEXT NOT NULL,
    current_temp_c REAL NOT NULL,
    today_high_c REAL NOT NULL,
    humidity REAL,
    wind_dir_deg REAL,
    wind_speed_ms REAL,
    radiation_global REAL,
    radiation_direct REAL,
    radar_status TEXT,
    satellite_status TEXT,
    recent_slope_10m REAL,
    recent_slope_30m REAL,
    recent_slope_60m REAL
);

CREATE INDEX IF NOT EXISTS idx_weather_snapshots_market_time
ON weather_snapshots (market_key, observed_at);
"""


def sqlite_path_from_url(database_url: str | None = None) -> Path:
    url = database_url or settings.database_url
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise ValueError(f"only sqlite:/// database URLs are supported for now: {url}")
    path_text = url[len(prefix) :]
    path = Path(path_text)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def connect(database_url: str | None = None) -> sqlite3.Connection:
    path = sqlite_path_from_url(database_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_weather_snapshot(snapshot: WeatherSnapshot, database_url: str | None = None) -> int:
    values = asdict(snapshot)
    values["observed_at"] = snapshot.observed_at.isoformat()
    values["saved_at"] = datetime.now(snapshot.observed_at.tzinfo).isoformat()

    columns = [
        "market_key",
        "station",
        "observed_at",
        "saved_at",
        "current_temp_c",
        "today_high_c",
        "humidity",
        "wind_dir_deg",
        "wind_speed_ms",
        "radiation_global",
        "radiation_direct",
        "radar_status",
        "satellite_status",
        "recent_slope_10m",
        "recent_slope_30m",
        "recent_slope_60m",
    ]

    with connect(database_url) as conn:
        cursor = conn.execute(
            f"INSERT INTO weather_snapshots ({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            [values.get(col) for col in columns],
        )
        conn.commit()
        return int(cursor.lastrowid)


def load_recent_snapshots(
    market_key: str,
    hours: int = 8,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    since = datetime.now().astimezone() - timedelta(hours=hours)
    with connect(database_url) as conn:
        rows = conn.execute(
            """
            SELECT * FROM weather_snapshots
            WHERE market_key = ? AND observed_at >= ?
            ORDER BY observed_at ASC, id ASC
            """,
            (market_key, since.isoformat()),
        ).fetchall()
    return [dict(row) for row in rows]


def latest_snapshot(market_key: str, database_url: str | None = None) -> dict[str, Any] | None:
    with connect(database_url) as conn:
        row = conn.execute(
            """
            SELECT * FROM weather_snapshots
            WHERE market_key = ?
            ORDER BY observed_at DESC, id DESC
            LIMIT 1
            """,
            (market_key,),
        ).fetchone()
    return dict(row) if row else None
