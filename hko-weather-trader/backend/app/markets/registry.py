from dataclasses import dataclass
from typing import Literal


MarketType = Literal["city_station_high", "airport_high", "official_station_high"]


@dataclass(frozen=True)
class East8Market:
    key: str
    name: str
    timezone: str
    market_type: MarketType
    primary_station: str
    country_or_region: str
    settlement_note: str
    priority: int


EAST8_MARKETS: dict[str, East8Market] = {
    "hk_hko_daily_high": East8Market(
        key="hk_hko_daily_high",
        name="香港 HKO 总部站日最高温",
        timezone="Asia/Hong_Kong",
        market_type="official_station_high",
        primary_station="HKO / HK Observatory",
        country_or_region="Hong Kong",
        settlement_note="只看香港天文台总部站，不混用全香港平均。",
        priority=0,
    ),
    "kr_rksi_daily_high": East8Market(
        key="kr_rksi_daily_high",
        name="首尔/仁川机场日最高温",
        timezone="Asia/Seoul",
        market_type="airport_high",
        primary_station="RKSI",
        country_or_region="South Korea",
        settlement_note="必须确认盘口是否按 RKSI METAR 或其他官方站结算。",
        priority=1,
    ),
    "jp_rjtt_daily_high": East8Market(
        key="jp_rjtt_daily_high",
        name="东京/羽田机场日最高温",
        timezone="Asia/Tokyo",
        market_type="airport_high",
        primary_station="RJTT",
        country_or_region="Japan",
        settlement_note="必须确认盘口是机场 METAR 还是东京官方站。",
        priority=1,
    ),
    "tw_taipei_daily_high": East8Market(
        key="tw_taipei_daily_high",
        name="台北官方站日最高温",
        timezone="Asia/Taipei",
        market_type="city_station_high",
        primary_station="TBD",
        country_or_region="Taiwan",
        settlement_note="先确认盘口指定的官方结算站点。",
        priority=1,
    ),
    "cn_zgsz_daily_high": East8Market(
        key="cn_zgsz_daily_high",
        name="深圳宝安机场日最高温",
        timezone="Asia/Shanghai",
        market_type="airport_high",
        primary_station="ZGSZ",
        country_or_region="China",
        settlement_note="优先 METAR 和深圳开放数据机场附近格点。",
        priority=2,
    ),
    "cn_beijing_airport_daily_high": East8Market(
        key="cn_beijing_airport_daily_high",
        name="北京机场日最高温",
        timezone="Asia/Shanghai",
        market_type="airport_high",
        primary_station="ZBAA/ZBAD",
        country_or_region="China",
        settlement_note="需要按盘口确认首都机场、大兴机场或城市官方站。",
        priority=2,
    ),
}


def get_market(key: str) -> East8Market:
    try:
        return EAST8_MARKETS[key]
    except KeyError as exc:
        raise ValueError(f"unknown market key: {key}") from exc
