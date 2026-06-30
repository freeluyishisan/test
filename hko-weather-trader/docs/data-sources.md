# 数据源规划

## 数据源原则

```text
优先官方结算源
优先站点级数据
优先分钟级/近实时数据
禁止混用城市平均代替结算站点
```

## P0：香港 HKO

### 必抓

| 数据 | 用途 |
|---|---|
| text_readings_e/c | 当前温度、今日最高，通常更新快 |
| hko.csv | HKO 分钟级/近实时站点数据 |
| AWS1_v2 | 站点读数备用源 |
| latest_1min_temperature.csv | 1 分钟站点表备用 |
| King's Park 辐射 | 判断太阳加热能力 |
| 雷达 | 判断雨区压制 |
| 卫星云图 | 判断云厚/云缝 |
| 风向风速 | 判断海风/降温 |

### HKO 标准字段

```text
station = HKO / HK Observatory
current_temp_c
observed_at
today_high_c
today_low_c
humidity
wind_dir
wind_speed
radiation_global
radiation_direct
radar_status
satellite_status
```

## P1：韩国首尔 / 仁川机场 RKSI

优先数据：

```text
METAR RKSI
TAF RKSI
KMA 官方观测
Open-Meteo / GFS 作为背景
雷达/云图作为修正
```

重点：

```text
METAR 温度多为整数
需要确认盘口按机场还是城市站结算
海风、云量、雷阵雨对最高温影响大
```

## P1：日本东京

候选站点：

```text
RJTT / 羽田机场
东京官方气象站
盘口指定结算源
```

优先数据：

```text
METAR / JMA 官方观测
JMA 预报
雷达/卫星
Open-Meteo / GFS 背景
```

## P1：台湾台北

候选数据：

```text
台湾气象署官方站点
台北测站
机场站 RCTP / RCSS，视盘口规则决定
雷达/卫星
数值预报背景
```

## P2：深圳 / 北京

深圳：

```text
深圳开放数据
宝安机场附近格点
METAR ZGSZ
官方站点
```

北京：

```text
METAR ZBAA / ZBAD
中国天气官方/机场数据
数值预报背景
```

## 数据质量检查

每条数据必须检查：

```text
时间戳是否新鲜
站点是否匹配
单位是否正确
是否为当天数据
是否出现跳变异常
是否和备用源冲突
```

## 数据降级规则

```text
主源失败 → 使用备用源，但标记 source_degraded
雷达失败 → 不做雨区精确到达判断
卫星失败 → 不做云厚精确判断
温度源过期 → 不输出交易建议
站点不匹配 → 直接阻断交易信号
```
