# contract_recon.py

EVM 合约函数侦察工具——把字节码里的所有函数挖出来、反查名字、自动评估危险等级。

## ⚠️ 仅做侦察用途

本脚本**只读、只做静态调用探测**，不会发任何写交易、不会动你的私钥。
适合用来：
- 审计自己写的合约（查漏补缺）
- 评估第三方合约的中心化风险
- 学习 EVM 合约的底层结构
- 复盘攻击事件（理解攻击者侦察手法）

## 安装

```bash
pip install -r requirements.txt
```

## 用法

### 基础用法（用默认 Arbitrum RPC）

```bash
python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
```

### 指定 RPC

```bash
# 以太坊主网
python contract_recon.py 0xYourContract --rpc https://eth.llamarpc.com

# Arbitrum
python contract_recon.py 0xYourContract --rpc https://arb1.arbitrum.io/rpc

# BSC
python contract_recon.py 0xYourContract --rpc https://bsc-dataseed.binance.org
```

### 输出 JSON 报告

```bash
python contract_recon.py 0x68d319... --out report.json
```

### 快速模式（跳过静态调用探测）

```bash
python contract_recon.py 0x68d319... --no-probe
```

## 它能挖出什么？

```
🔴 RED      高危：能直接搬钱（withdraw / drain / sweep / claim / harvest...）
🟠 ORANGE   橙危：能改权限（transferOwnership / upgrade / setAdmin...）
🟡 YELLOW   中危：能改状态（mint / pause / setFee...）
🟢 GREEN    安全：只读函数（owner / balanceOf / totalSupply...）
⚪ UNKNOWN  未识别：字典查不到名字的私有函数
```

## 工作原理

1. **拉字节码** + 自动检测 EIP-1967 代理（同时扫实现合约）
2. **提取选择器**：PUSH4 全字节码扫 + dispatcher 模式精确识别
3. **反查函数名**：4byte.directory + Openchain + 内置高频字典
4. **危险评估**：函数名匹配高危关键词
5. **碰撞检测**（重要）：
   - 字典碰撞：同一选择器对应多个签名时自动区分真实/垃圾
   - 代理碰撞：检测代理 ↔ 实现合约之间的选择器冲突（Audius-style 漏洞前置条件）
   - 垃圾签名识别：自动过滤 4byte 里被爆破污染的占位名字
6. **静态调用探测**：区分 view / 写函数 / 需要参数
7. **字符串提取**：找出错误信息辅助理解函数语义
8. **历史交易抓样**：（可选）从浏览器 API 拉正常调用样本

## 关于函数选择器碰撞

EVM 选择器只有 4 字节（2³² 空间），存在两类碰撞风险：

### 1. 被动碰撞（数据库噪音）

4byte.directory 里同一选择器常常对应多个签名：

```
0xa9059cbb:
  ✅ transfer(address,uint256)              ← 真实的 ERC20 transfer
  ⚠️  workMyDirefulOwner(uint256,uint256)   ← 爆破生成的垃圾名字
  ⚠️  join_tg_invmru_haha_fd06787(...)       ← hashbreaker 工具产物
  ⚠️  func_2093253501(bytes)                ← 自动占位
```

本工具通过 `classify_signature()` 自动识别并过滤这些"字典污染"，
只保留看着像真实业务函数的签名展示给你。

### 2. 主动碰撞攻击（真实漏洞）

攻击者可以**故意构造一个函数名让选择器与目标函数撞上**——
代理合约里的"无害查询函数"和实现合约里的"治理函数"如果撞了选择器，
就会出现权限绕过。

**真实案例**：[Audius hack（2022, $6M）](https://blog.audius.co/article/audius-governance-takeover-post-mortem-7-23-22)
就是攻击者构造的恶意函数选择器与 `initialize()` 碰撞，
绕过 owner 检查直接 re-initialize 治理合约。

本工具在扫到代理合约时会**自动对比代理和实现合约的选择器集合**，
发现冲突立即报告 `CRITICAL` 级别警告。

## 案例：扫描 AutoForwarder

```bash
python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
```

预期输出：
```
📦 字节码大小: 1409 字节
🔍 扫描出选择器: 共 3 个候选, 其中 3 个高置信度

╔════════╦══════════════╦═══════════════════════════════╦═══════════════════════════╗
║ 等级   ║ 选择器        ║ 函数签名                       ║ 静态调用结果              ║
╠════════╬══════════════╬═══════════════════════════════╬═══════════════════════════╣
║ 🟡     ║ 0xb7760c8f   ║ transfer(uint256,address)     ║ ⚠️  revert（需要参数...）  ║
║ 🟢     ║ 0xf851a440   ║ admin()                       ║ ✅ 调用成功，返回 32 字节  ║
║ 🟢     ║ 0x9d76ea58   ║ token() / factory()           ║ ✅ 调用成功，返回 32 字节  ║
╚════════╩══════════════╩═══════════════════════════════╩═══════════════════════════╝
```

## 结论解读

如果你的合约扫出来：
- **🔴 红色函数** > 0 个 → 务必检查每个都有严格的 onlyOwner / onlyRole
- **🟠 橙色函数** > 0 个 → 这些 owner 应该是多签 + Timelock，不能是单 EOA
- **代理合约** → 检查 ProxyAdmin 不是单 EOA

## 局限性

- 只能找出 **public/external 函数**（internal/private 函数没有选择器）
- 选择器哈希反查可能有同名碰撞（一个 4 字节对应多个签名）
- 参数**类型**能精确推断，但参数**语义**只能靠函数体逻辑推测
- 高度优化或 viaIR 编译的合约 dispatcher 模式可能识别不全（仍能靠 PUSH4 兜底）

## 进阶：配合 Heimdall 做完整反编译

如果想看每个函数的**完整代码逻辑**，建议配合 Heimdall：

```bash
# 安装
cargo install --git https://github.com/Jon-Becker/heimdall-rs heimdall

# 反编译
heimdall decompile --rpc-url $RPC 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
```

本脚本主要做"广度侦察"，Heimdall 做"深度反编译"，两者互补。
