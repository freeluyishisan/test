# EVM 合约工具集

一套从「侦察」到「调用」到「攻防」的完整 EVM 合约工具，复盘 DIA / AutoForwarder 攻击事件衍生而来。

| 工具 | 用途 |
|---|---|
| 🔍 [`contract_recon.py`](#contract_reconpy) | **只读侦察**：把字节码里的所有函数挖出来、反查名字、危险等级评估、碰撞检测 |
| ⚡ [`contract_interact.py`](#contract_interactpy) | **完整交互**：调用 view 函数、发真实交易、模拟、编解码 calldata |
| 💥 [`selector_collide.py`](#selector_collidepy) | **碰撞构造**：暴力爆破能撞上目标 selector 的函数名（红队/审计向） |
| 📊 [`selector_stats.py`](#selector_statspy) | **频率分析**：批量分析合约选择器、跨链对比字节码 |
| 🔧 [`heimdall_integration.py`](#heimdall_integrationpy) | **深度反编译**：包装 Heimdall CLI，反汇编/反编译/CFG |

---

## 安装

```bash
pip install -r requirements.txt
```

可选（`heimdall_integration.py` 需要）：
```bash
cargo install --git https://github.com/Jon-Becker/heimdall-rs heimdall
```

---

## 多链 / 本地节点 一键切换

所有工具都支持 `--chain` 参数：

```
eth, arb, op, base, bsc, polygon, avax, scroll, linea, blast,
local (= http://127.0.0.1:8545), anvil, hardhat, sepolia, holesky
```

或者用 `--rpc` 直接给完整 URL，或者环境变量 `RPC_URL`。

```bash
# 默认 Arbitrum
python contract_recon.py 0x...

# 显式指定
python contract_recon.py 0x... --chain bsc
python contract_recon.py 0x... --rpc https://eth.llamarpc.com

# 本地 Anvil
python contract_interact.py read 0xToken "balanceOf(address)" 0xMe --chain local
```

---

## `contract_recon.py`

**纯侦察工具**，不会发任何交易、不需要私钥。

```bash
python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
```

输出：
- 字节码大小 + 是否代理合约
- 所有 public/external 函数选择器
- 函数名反查（4byte + Openchain + 内置字典）
- 危险等级标注（🔴RED / 🟠ORANGE / 🟡YELLOW / 🟢GREEN）
- **选择器碰撞检测**（字典污染 + 代理↔实现冲突）
- 字节码里的可见错误信息字符串
- 安全建议

详见之前的版本说明。

---

## `contract_interact.py`

**主力工具**——完整的合约交互能力，从 read 到 write。

### 子命令一览

```bash
python contract_interact.py info <addr>             # 查看合约函数列表
python contract_interact.py read <addr> <sig> [args] # 调用 view（不花钱）
python contract_interact.py call <addr> <sig> [args] # 智能调用，自动判断
python contract_interact.py write <addr> <sig> [args] --key $PK   # 发交易
python contract_interact.py simulate <addr> <sig> [args] --key $PK # 模拟
python contract_interact.py encode <sig> [args]     # 离线编码 calldata
python contract_interact.py decode <calldata>       # 解码 calldata
python contract_interact.py balance <addr>          # 查余额
python contract_interact.py nonce <addr>            # 查 nonce
python contract_interact.py raw <addr> <calldata>   # 原始 calldata 调用
```

### 私钥来源（按优先级）

1. `--key 0x...` 命令行参数
2. `--keystore ~/keys/wallet.json` keystore 文件（会交互式询问密码或读 `KEYSTORE_PASSWORD`）
3. 环境变量 `PRIVATE_KEY`
4. 环境变量 `KEYSTORE_PATH`

### 实战例子

```bash
# 查代币余额（Arbitrum）
python contract_interact.py read 0xUSDT "balanceOf(address)" 0x123... --chain arb

# 模拟一笔 USDT 转账，看会不会成功
python contract_interact.py write 0xUSDT \
    "transfer(address,uint256)" 0xRecipient "100 ether" \
    --key $PRIVATE_KEY --simulate

# 模拟通过后真发（会先模拟一遍兜底，加 -y 跳过交互确认）
python contract_interact.py write 0xUSDT \
    "transfer(address,uint256)" 0xRecipient "100 ether" \
    --key $PRIVATE_KEY -y

# 调用项目自定义函数（DAI rescue tokens）
python contract_interact.py write 0xVault \
    "rescueTokens(address,uint256)" 0xToken 1000000 \
    --keystore ~/keys/admin.json

# 编码 calldata（离线生成，配合 Safe 签名等）
python contract_interact.py encode \
    "approve(address,uint256)" 0xRouter "1000 ether"

# 解码不知道的 calldata
python contract_interact.py decode 0xa9059cbb000000000000000000000000...

# 本地 Anvil 测试
python contract_interact.py write 0xMyContract "setOwner(address)" 0xNewOwner \
    --chain local --key 0xac0974bec...
```

### 写交易时的安全检查链

每次 `write` 都会：

1. **估算 gas**（含 20% buffer）
2. **检查余额**够不够
3. **eth_call 模拟一遍**（兜底防止白扔 gas）
4. **打印交易摘要表格**（from / to / 函数 / 参数 / value / gas / 费用 / chainId / calldata）
5. **交互式确认**（`--yes` 跳过）
6. **签名 + 广播 + 等待回执**

如果模拟失败，默认会拒绝发送；要硬发请加 `--force`。

### EIP-1559 vs Legacy

- 默认 EIP-1559：`maxFeePerGas = baseFee × 2 + priority`，`priority = 1.5 gwei`
- 加 `--gas-price 50` 自动切到 legacy 模式
- 加 `--priority 3` 调整 EIP-1559 priority

---

## `selector_collide.py`

**进攻向**工具，用于研究函数选择器碰撞（Audius hack 那类漏洞）。

```bash
# 计算签名的选择器
python selector_collide.py check "transferOwnership(address)"

# 找一个能撞上 0xa9059cbb (transfer) 的"看起来无害"的函数名
python selector_collide.py find 0xa9059cbb \
    --templates "init,upgrade,collect,exec" \
    --params "|address|uint256|address,uint256" \
    --max 5000000

# 对比代理合约和实现合约的选择器（Audius 漏洞前置条件）
python selector_collide.py compare 0xProxy 0xImpl --rpc https://...
```

**用途**：
- 红队：测试代理合约是否能被构造的恶意函数攻击
- 蓝队：审计自己合约的代理 + 实现是否存在选择器冲突
- 教学：理解"主动选择器碰撞攻击"原理

---

## `selector_stats.py`

```bash
# 批量分析多个合约的选择器频率（addresses.txt 里每行一个地址）
python selector_stats.py topbatch addresses.txt --top 30 --chain arb

# 找还有哪些合约部署了同样的字节码（用 Sourcify）
python selector_stats.py find_addr 0x...

# 同一地址在多链查询字节码差异
python selector_stats.py crosschain 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
```

---

## `heimdall_integration.py`

需要先安装 [Heimdall](https://github.com/Jon-Becker/heimdall-rs)。

```bash
# 反编译合约成近似 Solidity
python heimdall_integration.py decompile 0x68d319... --rpc https://...

# 反汇编
python heimdall_integration.py disasm 0x68d319...

# 控制流图
python heimdall_integration.py cfg 0x68d319... --output ./cfg/

# 分析一笔具体交易
python heimdall_integration.py inspect 0x74b749d8...
```

---

## 安全提示 ⚠️

- **`contract_interact.py write`** 会真实发交易、真实花 gas
- 私钥/keystore 涉及资金安全，**请只在自己的设备/服务器跑**
- 推荐先 `--simulate` 验证，再加 `-y` 自动发送
- 默认开启 eth_call 兜底，只有 `--force` 才能在模拟失败时强发
- 链上数据是公开的，但**别把私钥写进代码**——用环境变量或 keystore

---

## 完整工作流示例（以 AutoForwarder 案例为例）

```bash
# 1. 侦察合约——找出所有函数 + 危险等级 + 碰撞警告
python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559

# 2. 深度反编译，看每个函数的具体逻辑
python heimdall_integration.py decompile 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559

# 3. 用 read 查关键状态
python contract_interact.py read 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 \
    "admin()" --chain arb

# 4. 想用 admin 私钥提币时（仅在你自己合法控制的合约上）
python contract_interact.py write 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 \
    "transfer(uint256,address)" 1000000 0xMyAddress \
    --keystore ~/keys/admin.json --simulate

# 5. 检查代理 ↔ 实现的选择器冲突
python selector_collide.py compare 0xProxy 0xImpl --rpc ...
```

---

## 局限性

- 只能找出 **public/external 函数**（internal/private 函数没有选择器）
- 选择器哈希反查可能有同名碰撞——本工具自动过滤垃圾签名
- 参数**类型**能精确推断，但参数**语义**只能靠函数体逻辑推测
- 高度优化或 viaIR 编译的合约 dispatcher 模式可能识别不全（仍能靠 PUSH4 兜底）
- `selector_collide.py find` 是 brute-force，4 字节空间需要 ~2³² 次哈希才能保证找到——一般几百万次能撞中
