# East-8 Weather Trader

东八区天气预测交易系统。第一阶段只做 **HKO / 香港天文台总部站**，后续扩展首尔、东京、台北、深圳/北京机场等东八区及邻近时区天气盘口。

> 当前阶段：规划 + 项目骨架。默认只做 paper trading，不默认自动下单。

## 核心目标

```text
天气数据采集 → 站点级 nowcasting → 盘口估值 → edge 判断 → paper trading → 复盘校准 → 半自动交易
```

系统不把“AI 预测”当唯一核心。真正核心是：

1. 明确盘口结算站点；
2. 快速抓到官方实时数据；
3. 判断未来 30–90 分钟是否还能刷新最高温；
4. 把模型概率和盘口价格比较；
5. 只在有足够 edge 时出手；
6. 所有预测都入库复盘。

## 第一阶段市场

| 优先级 | 地区 | 目标站点 | 用途 |
|---|---|---|---|
| P0 | 香港 | HKO / 香港天文台总部站 | 主力 MVP |
| P1 | 韩国首尔 | RKSI / 仁川机场 或盘口指定站 | 机场温度盘口 |
| P1 | 日本东京 | RJTT / 羽田 或盘口指定站 | 机场温度盘口 |
| P1 | 台湾台北 | 官方指定站 / 机场站 | 城市或机场盘口 |
| P2 | 深圳 | 宝安机场格点 / 官方站 | 东八区扩展 |
| P2 | 北京 | 首都/大兴机场 METAR 或官方站 | 东八区扩展 |

## HKO 第一版输出

每次运行输出：

```text
当前 HKO 温度
今日已录得最高温
未来 60 分钟最高温预测
全天最高温主区间
30/31/32/33°C YES 概率
Polymarket 盘口价格
模型 edge
建议：买 YES / 买 NO / 不碰
```

## 项目目录

```text
hko-weather-trader/
├── backend/app/
│   ├── config.py
│   ├── main.py
│   ├── markets/registry.py
│   ├── models/rule_model.py
│   └── strategy/edge.py
├── docs/
│   ├── architecture.md
│   ├── strategy-east8.md
│   ├── data-sources.md
│   └── roadmap.md
├── scripts/run_once.py
├── .env.example
├── docker-compose.yml
└── pyproject.toml
```

## 当前原则

- 只认盘口指定结算站点。
- HKO 不混用全香港平均，不用九天天气预报当主预测。
- 先 paper trading，禁止默认真下单。
- edge 不足不交易。
- 数据过期不交易。
- 预测必须可复盘。

## 下一步

1. 完成 HKO textonly / hko.csv / AWS1 数据采集。
2. 加入 King's Park 辐射、雷达、卫星云图、风向风速。
3. 建立未来 60 分钟最高温规则模型。
4. 接 Polymarket Gamma/CLOB 盘口。
5. 开始 paper trading 和每日复盘。
