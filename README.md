# EVM 合约工具集

一套从「侦察」到「调用」到「批量」到「攻防」的完整 EVM 合约工具集，复盘 DIA / AutoForwarder 攻击事件衍生而来。

## 工具一览

| 工具 | 用途 | 子命令数 |
|---|---|---|
| 🔍 [`contract_recon.py`](./contract_recon.py) | **只读侦察**：把字节码里的所有函数挖出来、反查名字、危险等级评估、碰撞检测 | 1 |
| ⚡ [`contract_interact.py`](./contract_interact.py) | **完整交互**：read / write / simulate / encode / decode / balance / nonce | 10 |
| 📦 [`batch_tx.py`](./batch_tx.py) | **批量交易**：批量 approve / transfer / drain / 任意 YAML 配置 | 5 |
| 🏦 [`flashloan.py`](./flashloan.py) | **闪电贷**：Aave V3 / Balancer V2 一键集成 + Solidity 模板生成 | 4 |
| 🛠 [`cast.py`](./cast.py) | **Foundry cast 兼容**：习惯 Foundry 的人直接用熟悉的命令风格 | 27 |
| 💥 [`selector_collide.py`](./selector_collide.py) | **碰撞构造**：暴力爆破能撞上目标 selector 的函数名（红队向） | 3 |
| 📊 [`selector_stats.py`](./selector_stats.py) | **频率分析**：批量分析合约选择器、跨链对比字节码 | 3 |
| 🔧 [`heimdall_integration.py`](./heimdall_integration.py) | **深度反编译**：包装 Heimdall CLI | 4 |

---

## 安装

```bash
pip install -r requirements.txt
```

可选（Heimdall 反编译需要）：
```bash
cargo install --git https://github.com/Jon-Becker/heimdall-rs heimdall
```

---

## 多链 / 本地节点 一键切换

所有工具都支持：

```
eth, arb, op, base, bsc, polygon, avax, scroll, linea, blast, mantle, celo,
local (= http://127.0.0.1:8545), anvil, hardhat, sepolia, holesky
```

```bash
python contract_recon.py 0x... --chain bsc          # 用预设
python contract_recon.py 0x... --rpc https://...    # 用自定义 URL
python contract_interact.py read 0x... "name()" --chain local   # 本地 Anvil
export RPC_URL=https://my-private-rpc.io            # 用环境变量
```

---

## 🔍 contract_recon.py — 纯侦察

```bash
# 标准用法
python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559

# 跳过静态调用（更快）
python contract_recon.py 0x... --no-probe

# JSON 报告
python contract_recon.py 0x... --out report.json
```

输出：危险等级标注（🔴RED / 🟠ORANGE / 🟡YELLOW / 🟢GREEN）+ 选择器碰撞警告 + 字节码字符串。

---

## ⚡ contract_interact.py — 主交互工具

```bash
# 信息
python contract_interact.py info     <addr>
python contract_interact.py balance  <addr>
python contract_interact.py nonce    <addr>

# 读
python contract_interact.py read <addr> "balanceOf(address)" 0xMe
python contract_interact.py read 0xToken "name()"

# 编/解码
python contract_interact.py encode "approve(address,uint256)" 0xRouter "1 ether"
python contract_interact.py decode 0xa9059cbb000000... --signature "transfer(address,uint256)"

# 模拟
python contract_interact.py simulate <addr> "<sig>" [args] --key $PK

# 写交易（真发，会花 gas）
python contract_interact.py write <addr> "<sig>" [args] --key $PK -y
python contract_interact.py write 0xToken "transfer(address,uint256)" 0xRecv "1 ether" \
    --keystore ~/keys/wallet.json
```

每次写交易会先 estimate gas → 检查余额 → eth_call 模拟 → 显示摘要表 → 交互确认 → 签名广播。

---

## 📦 batch_tx.py — 批量交易（新）

### 批量 read（Multicall3 一笔 RPC 拿 N 个返回）

```bash
python batch_tx.py read --chain arb --calls '[
  ["0xToken","totalSupply()"],
  ["0xToken","name()"],
  ["0xToken","decimals()"]
]'
```

### 批量 approve

```bash
# 一个 token 给多个 spender
python batch_tx.py approve --chain arb --key $PK \
    --token 0xUSDC \
    --spenders 0xRouter1,0xRouter2,0xRouter3 \
    --amount max

# 多个 token 给同一个 spender（典型授权场景）
python batch_tx.py approve --chain arb --key $PK \
    --tokens 0xUSDC,0xUSDT,0xDAI \
    --spender 0xRouter \
    --amount "1000 ether"
```

### 批量空投

```bash
# 命令行格式
python batch_tx.py transfer --chain arb --key $PK \
    --token 0xUSDC \
    --recipients "0xA:1000000,0xB:2000000,0xC:500000"

# CSV 文件（每行 addr,amount）
python batch_tx.py transfer --chain arb --key $PK \
    --token 0xUSDC --recipients-file ./airdrop.csv

# 不指定 --token 则发原生币 ETH
python batch_tx.py transfer --chain arb --key $PK \
    --recipients "0xA:0.1ether,0xB:0.2ether"
```

### Drain：把多个代币全部转走（合并资产 / rug 自救）

```bash
python batch_tx.py drain --chain arb --key $PK \
    --tokens 0xUSDC,0xUSDT,0xDAI,0xWETH \
    --to 0xColdWallet \
    --include-native    # 也把原生币（留 0.001 gas）一起 drain
```

### 任意批量 (YAML 配置文件)

```bash
python batch_tx.py run --chain arb --key $PK --config ./sample_batch.yaml
```

参考 [`sample_batch.yaml`](./sample_batch.yaml) 模板。

### 公共选项

```
--simulate              只模拟不发送
--yes / -y              跳过交互确认
--delay 2.0             每笔之间间隔秒数（默认 1s）
--continue-on-error     某笔失败时继续下一笔
--gas-limit             固定 gas limit
```

---

## 🏦 flashloan.py — 闪电贷（新）

```bash
# 1. 看池子地址 + 手续费
python flashloan.py info --chain arb

# 2. 生成 receiver 合约模板（你需要先部署它）
python flashloan.py generate --provider aave --output ./MyFlashLoan.sol
python flashloan.py generate --provider balancer --output ./MyFlashLoan.sol
# Balancer 闪电贷手续费是 0%！

# 3. 编 calldata（不发送）
python flashloan.py encode --provider aave \
    --receiver 0xYourDeployedReceiver \
    --asset 0xUSDC --amount "1000 ether" \
    --params 0xabcd...

# 4. 真发起闪电贷
python flashloan.py call --provider balancer --chain arb --key $PK \
    --receiver 0xYourReceiver \
    --tokens 0xUSDC,0xWETH --amounts "1000 ether,0.5 ether" \
    --params 0xabcd... --simulate
```

### 工作流（重要）

闪电贷 **必须从合约发起**，不能直接 EOA 调用：

1. 用 `flashloan.py generate --provider aave -o MyFlashLoan.sol` 生成模板
2. 在生成的合约 `_execute()` 函数里填写你的业务逻辑（套利/清算/还债）
3. 用 Foundry/Hardhat/Remix 编译 + 部署该合约到目标链
4. 用 `flashloan.py call --receiver 0xDeployed` 发起闪电贷

**Aave V3 手续费 = 0.05%，Balancer V2 手续费 = 0%**（推荐 Balancer）。

---

## 🛠 cast.py — Foundry cast 兼容（新）

如果你习惯 Foundry，直接用 `cast.py` 替代 Python 实现。**命令名/选项跟 Foundry cast 完全一致**。

### 调用与交易

```bash
# 静态调用
python cast.py call 0xToken "balanceOf(address)" 0xMe --rpc-url $RPC

# 带 returns 类型
python cast.py call 0xToken "name()(string)" --rpc-url $RPC

# 真发交易
python cast.py send 0xToken "transfer(address,uint256)" 0xRecv "1ether" \
    --rpc-url $RPC --private-key $PK

# 估 gas
python cast.py estimate 0xToken "transfer(address,uint256)" 0xRecv 1000 \
    --from 0xMe --rpc-url $RPC

# 广播已签名 raw tx
python cast.py publish 0x02f86b...
```

### 编码 / 反查

```bash
python cast.py keccak "transfer(address,uint256)"     # 算 keccak hash
python cast.py sig "transfer(address,uint256)"        # 算 selector
python cast.py 4byte 0xa9059cbb                       # 反查函数名
python cast.py calldata "approve(address,uint256)" 0xR "1ether"
python cast.py abi-encode "transfer(address,uint256)" 0xR 1000
python cast.py abi-decode "(uint256,address)" 0x000...
```

### 数据查询

```bash
python cast.py balance 0xMe --ether --rpc-url $RPC
python cast.py nonce 0xMe --rpc-url $RPC
python cast.py code 0xContract --rpc-url $RPC
python cast.py storage 0xContract 0 --rpc-url $RPC      # 读 slot 0
python cast.py block 100 --rpc-url $RPC
python cast.py block-number --rpc-url $RPC
python cast.py chain-id --rpc-url $RPC
python cast.py gas-price --gwei --rpc-url $RPC
python cast.py tx 0xHash --rpc-url $RPC
python cast.py receipt 0xHash --rpc-url $RPC
```

### 单位转换

```bash
python cast.py to-wei "1.5" ether          # 1500000000000000000
python cast.py from-wei 1500000000000000000 ether    # 1.5
python cast.py to-hex 1234                 # 0x4d2
python cast.py to-dec 0x4d2                # 1234
python cast.py to-checksum 0xabc...        # 转 checksum 地址
python cast.py to-ascii 0x44494100         # DIA
```

### 钱包

```bash
python cast.py wallet-new                    # 生成随机钱包
python cast.py wallet-address --private-key 0x...   # 私钥导地址
```

### 环境变量（同 Foundry）

```bash
export ETH_RPC_URL=https://...
export ETH_PRIVATE_KEY=0x...
export ETH_FROM=0xMe
```

---

## 💥 selector_collide.py — 碰撞构造

```bash
python selector_collide.py check "transferOwnership(address)"
python selector_collide.py find 0xa9059cbb --templates "init,upgrade,exec" --max 5000000
python selector_collide.py compare 0xProxy 0xImpl --rpc https://...
```

---

## 📊 selector_stats.py — 频率分析

```bash
python selector_stats.py topbatch addresses.txt --top 30 --chain arb
python selector_stats.py find_addr 0xContract
python selector_stats.py crosschain 0xContract
```

---

## 🔧 heimdall_integration.py — 深度反编译

```bash
python heimdall_integration.py decompile 0x... --rpc https://...
python heimdall_integration.py disasm 0x... --rpc ...
python heimdall_integration.py cfg 0x... --output ./cfg/
python heimdall_integration.py inspect 0xTxHash
```

---

## 安全提示 ⚠️

- **`contract_interact.py write` / `batch_tx.py` 写命令 / `cast.py send` / `flashloan.py call`** 会真实发交易、真实花 gas
- 私钥/keystore 涉及资金，**请只在自己的设备/服务器跑**
- 推荐先 `--simulate` 验证，再加 `-y` 自动发送
- 写交易默认会 eth_call 兜底，模拟失败拒绝发送（除非 `--force`）
- **别把私钥写进代码** —— 用环境变量或 keystore JSON

---

## 完整工作流示例（DIA / AutoForwarder 案例）

```bash
# 1. 侦察
python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 --chain arb

# 2. 反编译看函数体
python heimdall_integration.py decompile 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 \
    --rpc https://arb1.arbitrum.io/rpc

# 3. 用 cast 风格快速查 admin
python cast.py call 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 "admin()(address)" \
    --rpc-url https://arb1.arbitrum.io/rpc

# 4. 批量查所有相关合约状态
python batch_tx.py read --chain arb --calls '[
  ["0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559","admin()"],
  ["0x6eFa9b8883DFb78fD75CD89d8474C44c3CBDa469","totalSupply()"],
  ["0x6eFa9b8883DFb78fD75CD89d8474C44c3CBDa469","name()"]
]'

# 5. 想用 admin 私钥提币（仅在你合法控制的合约上）
python contract_interact.py write 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 \
    "transfer(uint256,address)" 1000000 0xMyAddress \
    --keystore ~/keys/admin.json --simulate
```
