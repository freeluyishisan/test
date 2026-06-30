import csv
import re
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from zoneinfo import ZoneInfo

HK_TZ = ZoneInfo("Asia/Hong_Kong")


@dataclass(frozen=True)
class HkoStationReading:
    source: str
    station: str
    observed_at: datetime | None
    fetched_at: datetime
    current_temp_c: float | None = None
    today_high_c: float | None = None
    today_low_c: float | None = None
    humidity: float | None = None
    pressure_hpa: float | None = None
    global_solar_wm2: float | None = None
    direct_solar_wm2: float | None = None
    diffuse_solar_wm2: float | None = None
    raw_line: str | None = None


def _to_float(value: str | int | float | None) -> float | None:
    if value is None:
        return None
    text = str(value).strip().replace("+", "")
    if not text or text.upper() == "N/A":
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_textonly_observed_at(body: str, fetched_at: datetime) -> datetime | None:
    """Parse line like: Latest readings recorded at 07:10 Hong Kong Time 30 June 2026."""
    pattern = re.compile(
        r"Latest readings recorded at\s+(\d{1,2}:\d{2})\s+Hong Kong Time\s+(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})",
        re.IGNORECASE,
    )
    match = pattern.search(body)
    if not match:
        return None

    time_text, day, month_name, year = match.groups()
    try:
        parsed = datetime.strptime(
            f"{day} {month_name} {year} {time_text}", "%d %B %Y %H:%M"
        )
        return parsed.replace(tzinfo=HK_TZ)
    except ValueError:
        return None


def parse_hko_textonly(body: str, fetched_at: datetime | None = None) -> HkoStationReading:
    """Parse HKO textonly page and return the HK Observatory row.

    Current live format uses fixed-width text, e.g.
    HK Observatory 26.6 94 28.7 / 26.4 -0.3
    """
    fetched_at = fetched_at or datetime.now(HK_TZ)
    observed_at = parse_textonly_observed_at(body, fetched_at)

    target_line = None
    for line in body.splitlines():
        if "HK Observatory" in line or "Hong Kong Observatory" in line:
            # Avoid pressure section if possible. The temperature row contains " / ".
            if " / " in line or target_line is None:
                target_line = line.rstrip()
                if " / " in line:
                    break

    if not target_line:
        raise ValueError("HK Observatory row not found in HKO textonly body")

    # Capture station, current temp, humidity, max/min.
    match = re.search(
        r"(?P<station>HK Observatory|Hong Kong Observatory)\s+"
        r"(?P<temp>N/A|-?\d+(?:\.\d+)?)\s+"
        r"(?P<humidity>N/A|-?\d+(?:\.\d+)?)\s+"
        r"(?P<high>N/A|-?\d+(?:\.\d+)?)\s*/\s*"
        r"(?P<low>N/A|-?\d+(?:\.\d+)?)",
        target_line,
    )
    if not match:
        raise ValueError(f"failed to parse HK Observatory textonly row: {target_line!r}")

    return HkoStationReading(
        source="hko_textonly",
        station=match.group("station"),
        observed_at=observed_at,
        fetched_at=fetched_at,
        current_temp_c=_to_float(match.group("temp")),
        humidity=_to_float(match.group("humidity")),
        today_high_c=_to_float(match.group("high")),
        today_low_c=_to_float(match.group("low")),
        raw_line=target_line,
    )


def parse_hko_rhrread(payload: dict, fetched_at: datetime | None = None) -> HkoStationReading:
    """Parse official rhrread JSON for Hong Kong Observatory temperature and humidity.

    rhrread temperature is usually integer °C, so it is a validation/fallback source,
    not the preferred HKO trading source when textonly/hko.csv is available.
    """
    fetched_at = fetched_at or datetime.now(HK_TZ)

    update_time = payload.get("updateTime")
    observed_at = None
    if isinstance(update_time, str):
        try:
            observed_at = datetime.fromisoformat(update_time)
        except ValueError:
            observed_at = None

    temp_value = None
    for item in payload.get("temperature", {}).get("data", []):
        if item.get("place") in {"Hong Kong Observatory", "HK Observatory"}:
            temp_value = _to_float(item.get("value"))
            break

    humidity_value = None
    for item in payload.get("humidity", {}).get("data", []):
        if item.get("place") in {"Hong Kong Observatory", "HK Observatory"}:
            humidity_value = _to_float(item.get("value"))
            break

    return HkoStationReading(
        source="hko_rhrread",
        station="Hong Kong Observatory",
        observed_at=observed_at,
        fetched_at=fetched_at,
        current_temp_c=temp_value,
        humidity=humidity_value,
    )


def parse_hko_csv(csv_text: str, fetched_at: datetime | None = None) -> HkoStationReading:
    """Parse hko.csv with defensive logic.

    HKO CSV formats have changed over time. This parser first looks for a row containing
    HK Observatory / Hong Kong Observatory, then extracts plausible numeric fields.
    It treats the first plausible temperature-like value as current temp when headers are unknown.
    """
    fetched_at = fetched_at or datetime.now(HK_TZ)
    reader = csv.reader(StringIO(csv_text))
    rows = [row for row in reader if row]

    target = None
    for row in rows:
        joined = " ".join(cell.strip() for cell in row)
        if "HK Observatory" in joined or "Hong Kong Observatory" in joined:
            target = row
            break

    if not target:
        raise ValueError("HK Observatory row not found in hko.csv")

    station = "HK Observatory" if "HK Observatory" in " ".join(target) else "Hong Kong Observatory"
    numeric_values = [_to_float(cell) for cell in target]
    numeric_values = [value for value in numeric_values if value is not None]

    # Temperature range for Hong Kong practical observations.
    temp_candidates = [value for value in numeric_values if 0 <= value <= 45]
    current_temp = temp_candidates[0] if temp_candidates else None

    return HkoStationReading(
        source="hko_csv",
        station=station,
        observed_at=None,
        fetched_at=fetched_at,
        current_temp_c=current_temp,
        raw_line=",".join(target),
    )


def parse_textonly_king_park_radiation(
    body: str, fetched_at: datetime | None = None
) -> HkoStationReading | None:
    """Parse King's Park solar radiation row from textonly page if present."""
    fetched_at = fetched_at or datetime.now(HK_TZ)
    for line in body.splitlines():
        if "King's Park" not in line:
            continue
        values = re.findall(r"-?\d+(?:\.\d+)?", line)
        # The radiation row normally has three values around W/m^2. Other King's Park rows exist.
        if len(values) >= 3 and "Radiation" not in line:
            nums = [_to_float(v) for v in values[-3:]]
            if nums[0] is not None and nums[0] >= 0 and nums[1] is not None and nums[2] is not None:
                # Heuristic: global/direct/diffuse radiation row often appears near page bottom.
                if nums[0] > 30 or nums[1] >= 0 or nums[2] > 30:
                    return HkoStationReading(
                        source="hko_textonly_radiation",
                        station="King's Park",
                        observed_at=parse_textonly_observed_at(body, fetched_at),
                        fetched_at=fetched_at,
                        global_solar_wm2=nums[0],
                        direct_solar_wm2=nums[1],
                        diffuse_solar_wm2=nums[2],
                        raw_line=line.rstrip(),
                    )
    return None
