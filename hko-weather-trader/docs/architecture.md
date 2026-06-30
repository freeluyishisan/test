# 系统架构

## 总体设计

```text
官方天气源
  ↓
采集器 collectors
  ↓
标准化数据 snapshots
  ↓
特征计算 features
  ↓
预测模型 models
  ↓
盘口模块 markets
  ↓
edge / 风控 / 仓位
  ↓
paper trading / 半自动下单
  ↓
复盘校准 reports
```

## 模块职责

### 1. 数据采集层

负责抓官方数据，不做交易判断。

第一阶段 HKO：

```text
text_readings_e / text_readings_c
hko.csv
AWS1_v2
latest_1min_temperature.csv
King's Park 辐射
雷达
卫星云图
```

扩展市场：

```text
RKSI / RJTT / 北京 / 深圳：METAR、官方站点、开放数据、数值预报
台北：官方站点或盘口指定结算源
```

### 2. 标准化层

所有市场统一成：

```json
{
  "market_key": "hk_hko_daily_high",
  "timezone": "Asia/Hong_Kong",
  "station": "HKO",
  "observed_at": "2026-06-30T14:10:00+08:00",
  "current_temp_c": 30.6,
  "today_high_c": 30.8,
  "humidity": 72,
  "wind_dir_deg": 180,
  "wind_speed_ms": 3.2,
  "radiation_global": 620,
  "radar_status": "clear_near_station",
  "satellite_status": "thin_cloud"
}
```

### 3. 特征层

核心特征：

```text
当前温度
今日最高
距离阈值差
近 10/30/60 分钟升温斜率
当前时段
辐射强弱
云图厚度
雷达雨区距离
风向风速变化
湿度变化
近邻站同步性
```

### 4. 预测层

第一版使用规则模型：

```text
已录得最高温规则
未来 60 分钟冲高规则
全天最高温区间规则
阈值概率规则
```

后续再加：

```text
历史同月统计
LightGBM / XGBoost
概率校准
Brier score
```

### 5. 盘口层

负责 Polymarket：

```text
市场搜索
slug 解析
token_id 管理
YES/NO 价格
订单簿深度
最新成交
盘口隐含概率
```

### 6. 交易决策层

交易判断公式：

```text
edge = model_probability - market_price
```

默认规则：

```text
edge >= 12%：强信号
edge 8%–12%：小仓候选
edge 4%–8%：观察
edge < 4%：不碰
```

### 7. 风控层

硬规则：

```text
数据过期不交易
站点不匹配不交易
盘口深度不足不交易
edge 不足不交易
雷暴突变期降级
自动交易默认关闭
```

### 8. 复盘层

每日输出：

```text
预测最高温 vs 实际最高温
每个阈值概率命中情况
Brier score
模拟收益
错因分类
下一日参数修正建议
```
