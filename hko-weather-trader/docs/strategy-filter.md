# 开源策略筛选：保留可赚钱逻辑，删除噪音

## 目标

不是把 GitHub 上所有策略都塞进系统，而是筛出对东八区天气盘口有真实转化价值的部分。

核心判断标准：

```text
是否能改善真实概率判断
是否能改善入场价格
是否能降低错误交易
是否适配 HKO / 机场站点结算
是否可复盘校准
```

不满足这些条件的策略，先不进主系统。

---

## 参考开源项目

### 1. polymarket-kalshi-weather-bot

可保留逻辑：

```text
ensemble 概率
model_probability - market_probability = edge
限制极端概率
最大入场价过滤
Kelly / 仓位上限
信号落库
```

它的天气策略本质：

```text
集合预报成员超过阈值的比例 = 模型概率
模型概率 - 盘口价格 = edge
edge 超过阈值才交易
```

对 HKO 的改造：

```text
不能只用 Open-Meteo / GFS ensemble
必须加入 HKO 实时温度、今日最高、分钟级升温斜率、辐射、雷达、云图、风向
```

### 2. boz-weather-trader

可保留逻辑：

```text
多源天气数据
ML / 统计模型融合
正期望交易
Kelly sizing
每日亏损限制
敞口限制
Brier score
MAE/RMSE/bias
trade post-mortem
```

对 HKO 的改造：

```text
第一阶段不用复杂 ML
先用规则模型 + paper trading 校准
有 7–14 天数据后再加 LightGBM/XGBoost
```

### 3. Kalshi-Weather-Trading proposal

可保留逻辑：

```text
维护理论 fair price
用历史交易判断 incoming trades 是否有信息价值
根据概率分布迁移做 YES/NO 组合
```

适配 HKO：

```text
当主概率从 30°C 移到 31°C：
  30°C YES 不追
  31°C YES 找低估
  32°C YES 只在辐射/升温强时小概率观察
```

### 4. Prediction-Markets-Trading-Bot-Toolkits

可保留逻辑：

```text
Depth Guard
Circuit Breaker
Dry Run
Trade Floor
Resolution Sniper
Cross-Market Arbitrage
Orderbook Imbalance
Market Making 的库存控制思想
```

注意：这些主要是执行层和风控层，不是天气预测核心。

### 5. BTC / 短周期盘口 bot

大部分不适合天气市场。

可保留很少：

```text
入场窗口
最大入场价
只在外部信号和盘口方向一致时入场
```

必须删除：

```text
BTC 动量
BTC mean reversion
纯 odds favorite
纯 contrarian
follow_odds
```

---

## 策略白名单

### A. 站点 nowcasting

保留。

理由：最适合 HKO。

输入：

```text
当前温度
今日最高
近 10/30/60 分钟升温
辐射
雷达
云图
风向风速
湿度
当前时段
```

输出：

```text
未来 60 分钟最高温
全天最高温区间
各阈值 YES 概率
```

### B. Edge 定价

保留。

公式：

```text
edge = model_probability - market_price
```

规则：

```text
edge < 4%：噪音
4%–8%：观察
8%–12%：候选
>=12%：强信号
```

### C. 最大入场价过滤

保留。

规则：

```text
YES 价格 > 0.75：一般不追，除非已经实质命中
NO 价格 > 0.75：一般不追，除非突破概率已经崩塌
```

### D. 数据新鲜度过滤

保留。

规则：

```text
HKO 温度源超过 3 分钟未更新：不交易
盘口价格超过 30 秒未更新：不交易
站点不匹配：不交易
```

### E. 订单簿深度过滤

保留。

规则：

```text
建议仓位无法在最大滑点内成交：不交易
盘口太薄：只观察
```

### F. Resolution Sniper

有限保留。

适合场景：

```text
HKO 已录得阈值
YES 价格仍低于 0.97
或已经过决胜窗口，NO 明显被低估
```

限制：

```text
必须确认结算源已明确命中/失败
不允许只凭感觉做 95¢ 合约
```

### G. 信息流/盘口异动辅助

有限保留。

用途：

```text
大单只能作为提醒
不能直接作为交易信号
```

有效条件：

```text
大单方向与 HKO 实时数据、升温斜率、辐射/雷达一致
```

---

## 策略黑名单

### 1. 纯跟随盘口热门方向

删除。

原因：

```text
天气盘口热门方向很多时候已经反映信息
没有站点数据 edge
容易高价接盘
```

### 2. 纯反向赔率策略

删除。

原因：

```text
天气不是均值回归盘口
高价合约可能确实接近结算
低价合约可能确实没机会
```

### 3. BTC 动量类

删除。

原因：

```text
和天气结算无关
不能迁移到 HKO
```

### 4. Sports Execution

删除。

原因：

```text
东八区天气系统不做体育盘口
```

### 5. Copy Trading

删除为主，保留观察。

原因：

```text
不知道对方是否懂 HKO 结算源
容易复制噪音钱包
```

可作为辅助：

```text
长期记录某钱包在天气盘口的表现
证明有 alpha 后才加入观察，不直接跟单
```

### 6. 高频 spread farming

暂时删除。

原因：

```text
需要低延迟执行和稳定盘口深度
天气盘口流动性不一定够
容易被滑点和撤单吃掉
```

### 7. Market Making

暂时删除。

原因：

```text
第一阶段目标是预测 edge，不是做流动性提供者
库存风险复杂
```

---

## HKO 交易信号过滤器

候选交易必须同时满足：

```text
station_ok = True
fresh_weather_data = True
threshold_probability_calibrated = True
edge >= 0.08
orderbook_depth_ok = True
not_in_no_trade_window = True
not_source_degraded_critical = True
```

否则输出：

```text
NO_TRADE
```

## 禁止交易原因枚举

```text
STALE_WEATHER_DATA
STATION_MISMATCH
EDGE_TOO_SMALL
ENTRY_PRICE_TOO_HIGH
ORDERBOOK_TOO_THIN
RADAR_OR_SATELLITE_MISSING_NEAR_DECISION_WINDOW
MODEL_NOT_CALIBRATED
SOURCE_CONFLICT
POST_PEAK_NO_FRESH_HIGH
UNKNOWN_SETTLEMENT_RULE
```

---

## 当前系统主策略

第一阶段只启用：

```text
HKO_NOWCAST_EDGE
DATA_FRESHNESS_FILTER
ENTRY_PRICE_FILTER
PAPER_TRADING_ONLY
```

暂不启用：

```text
COPY_TRADING
PURE_ODDS_FAVORITE
PURE_CONTRARIAN
MARKET_MAKING
SPREAD_FARMING
BTC_MOMENTUM
SPORTS_EXECUTION
```

## 后续加入顺序

```text
1. HKO nowcasting + edge
2. 数据新鲜度 + 站点校验
3. 订单簿深度
4. Resolution sniper
5. 信息流辅助
6. 跨平台套利
7. ML 模型校准
```
