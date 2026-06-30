from datetime import datetime
from zoneinfo import ZoneInfo

from backend.app.collectors.hko_parsers import (
    parse_hko_rhrread,
    parse_hko_textonly,
    parse_textonly_king_park_radiation,
)


def test_parse_hko_textonly_row() -> None:
    body = """
Regional Weather in Hong Kong
Latest readings recorded at 07:10 Hong Kong Time 30 June 2026
    HK Observatory                 26.6       94        28.7 / 26.4       -0.3
Mean Sea Level Pressure (hPa)
    HK Observatory         1008.1
"""
    reading = parse_hko_textonly(body, datetime.now(ZoneInfo("Asia/Hong_Kong")))
    assert reading.station == "HK Observatory"
    assert reading.current_temp_c == 26.6
    assert reading.humidity == 94
    assert reading.today_high_c == 28.7
    assert reading.today_low_c == 26.4
    assert reading.observed_at is not None
    assert reading.observed_at.hour == 7
    assert reading.observed_at.minute == 10


def test_parse_rhrread_hko() -> None:
    payload = {
        "updateTime": "2026-06-30T07:02:00+08:00",
        "temperature": {
            "data": [
                {"place": "King's Park", "value": 26, "unit": "C"},
                {"place": "Hong Kong Observatory", "value": 27, "unit": "C"},
            ]
        },
        "humidity": {
            "data": [{"place": "Hong Kong Observatory", "value": 94, "unit": "percent"}]
        },
    }
    reading = parse_hko_rhrread(payload)
    assert reading.current_temp_c == 27
    assert reading.humidity == 94
    assert reading.observed_at is not None


def test_parse_king_park_radiation_only_after_header() -> None:
    body = """
Latest readings recorded at 07:10 Hong Kong Time 30 June 2026
    King's Park                    26.1       93        28.0 / 25.9       -0.3              24.9             23.4
                   Global Solar       Direct Solar       Diffuse Solar
                  Radiation (W/m^{2})   Radiation (W/m^{2})   Radiation (W/m^{2})
    Kau Sai Chau      115.0                0.0              116.0
    King's Park        95.0                0.0               88.0
N/A - data not available
"""
    reading = parse_textonly_king_park_radiation(body)
    assert reading is not None
    assert reading.global_solar_wm2 == 95.0
    assert reading.direct_solar_wm2 == 0.0
    assert reading.diffuse_solar_wm2 == 88.0
