# 路线图

## V0.1：规划与骨架

目标：把系统定位、数据源、策略和目录建好。

交付：

```text
README.md
docs/architecture.md
docs/strategy-east8.md
docs/data-sources.md
docs/roadmap.md
基础 Python 项目结构
```

## V0.2：HKO 数据采集

目标：只把 HKO 数据抓准。

任务：

```text
抓 text_readings_e/c
抓 hko.csv
抓 AWS1_v2
统一输出 WeatherSnapshot
校验时间戳和站点
```

验收：

```text
python scripts/run_once.py
能输出 HKO 当前温度、今日最高、数据时间戳
```

## V0.3：HKO 规则预测模型

目标：预测未来 60 分钟最高温和全天最高温区间。

任务：

```text
近 10/30/60 分钟升温斜率
当前时段权重
距离阈值差
辐射/雷达/云图占位
阈值概率输出
```

验收：

```text
输出 30/31/32/33°C YES 概率
输出交易解释
```

## V0.4：Polymarket 盘口接入

目标：获取市场价格和订单簿。

任务：

```text
Gamma 市场搜索
CLOB token_id 解析
YES/NO 价格
best bid / ask
订单簿深度
```

验收：

```text
模型概率 vs 盘口价格
edge 排序
```

## V0.5：Paper Trading

目标：先模拟，不真下单。

任务：

```text
信号入库
模拟成交
结算记录
模拟收益
```

验收：

```text
每天能看出如果按系统交易会赚还是亏
```

## V0.6：复盘校准

目标：让概率越来越准。

任务：

```text
温度误差 MAE
阈值 Brier score
edge 分层收益
错因分类
每日复盘报告
```

## V0.7：多市场扩展

新增：

```text
RKSI / 首尔机场
RJTT / 东京机场
台北官方站点
深圳宝安机场
北京机场
```

原则：每个市场必须先定义：

```text
结算站点
官方数据源
时间窗口
温度单位
更新时间频率
盘口规则
```

## V1.0：半自动交易

目标：系统只提醒，不默认自动下单。

输出：

```text
建议方向
最大入场价
建议仓位
止盈条件
止损条件
禁止交易原因
```

## V1.1：自动交易

前提：

```text
连续 paper trading 有正收益
Brier score 稳定
edge 分层有效
盘口深度足够
实盘小仓验证通过
```

默认仍关闭自动交易。
