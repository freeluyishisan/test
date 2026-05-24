#!/usr/bin/env python3
"""
contract_recon.py —— EVM 合约函数侦察工具
============================================
用途：对任意 EVM 合约做"白盒级别"的函数发现 + 参数推断 + 危险等级评估。
原理：综合"字节码 PUSH4 扫描 + dispatcher 模式识别 + 4byte/Openchain 反查
      + EIP-1967 代理跟踪 + 静态调用探测 + 字符串提取 + 历史 calldata 抓样"。

⚠️  只读、只做侦察。本脚本不发任何交易。

依赖：pip install web3 requests rich
用法：python contract_recon.py <合约地址> [--rpc <RPC_URL>] [--out report.json]

例子：
    python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
    python contract_recon.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559 \
        --rpc https://arb1.arbitrum.io/rpc --out autoforwarder.json
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests
from web3 import Web3

# rich 只用来美化输出，没装也能跑
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class _FakeConsole:
        def print(self, *a, **kw): print(*a)
    console = _FakeConsole()


# ============================================================================
# 配置区
# ============================================================================
DEFAULT_RPC = "https://arb1.arbitrum.io/rpc"  # Arbitrum One 公共节点

# EIP-1967 代理槽位（标准定义）
EIP1967_IMPL_SLOT  = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
EIP1967_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
EIP1967_BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50

# 高危函数关键词（用于打标签 / 定级别）
DANGER_KEYWORDS = {
    # 🔴 红色：能直接搬走资产
    "RED": [
        "withdraw", "drain", "sweep", "rescue", "recover", "emergency",
        "selfdestruct", "kill", "destruct", "destroy",
        "skim", "collect", "harvest", "claim", "redeem", "exit",
    ],
    # 🟠 橙色：能改变权限/合约状态
    "ORANGE": [
        "transferOwnership", "setOwner", "setAdmin", "addAdmin", "removeAdmin",
        "grantRole", "revokeRole", "renounceOwnership", "renounceRole",
        "upgrade", "upgradeTo", "setImplementation", "changeImpl",
        "initialize", "init", "setUp", "setup",
        "setMinter", "setManager", "setOperator", "setController",
        "setGovernance", "setTreasury",
    ],
    # 🟡 黄色：能动钱但有限制 / 改参数
    "YELLOW": [
        "mint", "burn", "pause", "unpause", "freeze",
        "setFee", "setRate", "setPair", "setRouter", "setOracle",
        "setWhitelist", "addToWhitelist", "blacklist",
        "transfer", "approve", "transferFrom",
    ],
    # 🟢 绿色：只读，安全
    "GREEN": [
        "owner", "admin", "balanceOf", "totalSupply", "name", "symbol",
        "decimals", "allowance", "implementation", "paused",
    ],
}

# 内置常用函数字典（4byte 不可达时备用）
BUILTIN_DICT = {
    # ERC20 / ERC721 标准
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0xdd62ed3e": "allowance(address,address)",
    "0x18160ddd": "totalSupply()",
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x313ce567": "decimals()",
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    # Ownable
    "0x8da5cb5b": "owner()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
    "0xf851a440": "admin()",
    # Pausable
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
    "0x5c975abb": "paused()",
    # 提款类高频
    "0x3ccfd60b": "withdraw()",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xf3fef3a3": "withdraw(address,uint256)",
    "0xdb2e21bc": "emergencyWithdraw()",
    "0x4e71d92d": "claim()",
    "0x372500ab": "claimRewards()",
    "0xb88a802f": "claimReward()",
    "0x4641257d": "harvest()",
    "0x3d18b912": "getReward()",
    "0xfc0c546a": "token()",
    "0x9d76ea58": "factory()",  # 也可能是 token() 的某种重命名
    # 代理升级
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1ef286": "upgradeToAndCall(address,bytes)",
    "0x5c60da1b": "implementation()",
    # AccessControl
    "0x91d14854": "hasRole(bytes32,address)",
    "0x2f2ff15d": "grantRole(bytes32,address)",
    "0xd547741f": "revokeRole(bytes32,address)",
    # 初始化
    "0x8129fc1c": "initialize()",
    "0xc4d66de8": "initialize(address)",
}


# ============================================================================
# 数据结构
# ============================================================================
@dataclass
class FunctionInfo:
    selector: str                             # 4 字节选择器
    signatures: list = field(default_factory=list)  # 反查到的人类可读签名
    danger_level: str = "UNKNOWN"             # RED / ORANGE / YELLOW / GREEN / UNKNOWN
    static_call_result: str = ""              # 静态调用结果
    likely_view: bool = False                 # 是否疑似 view 函数
    notes: list = field(default_factory=list) # 额外备注


# ============================================================================
# 模块 1：字节码获取 + 代理检测
# ============================================================================
def fetch_bytecode(w3: Web3, addr: str) -> bytes:
    """拉取 runtime 字节码"""
    return w3.eth.get_code(Web3.to_checksum_address(addr))

def detect_proxy(w3: Web3, addr: str) -> dict:
    """检测是否为 EIP-1967 代理，返回 {is_proxy, impl, admin, beacon}"""
    addr = Web3.to_checksum_address(addr)
    info = {"is_proxy": False, "impl": None, "admin": None, "beacon": None}

    impl_raw = w3.eth.get_storage_at(addr, EIP1967_IMPL_SLOT)
    impl_addr = "0x" + impl_raw.hex()[-40:]
    if int(impl_addr, 16) != 0:
        info["is_proxy"] = True
        info["impl"] = Web3.to_checksum_address(impl_addr)

    admin_raw = w3.eth.get_storage_at(addr, EIP1967_ADMIN_SLOT)
    admin_addr = "0x" + admin_raw.hex()[-40:]
    if int(admin_addr, 16) != 0:
        info["admin"] = Web3.to_checksum_address(admin_addr)

    beacon_raw = w3.eth.get_storage_at(addr, EIP1967_BEACON_SLOT)
    beacon_addr = "0x" + beacon_raw.hex()[-40:]
    if int(beacon_addr, 16) != 0:
        info["beacon"] = Web3.to_checksum_address(beacon_addr)
        info["is_proxy"] = True

    return info


# ============================================================================
# 模块 2：从字节码提取函数选择器
# ============================================================================
def extract_selectors(bytecode: bytes) -> set:
    """
    综合两种方法提取选择器：
    1. 全字节码 PUSH4 扫描（高召回，可能有误报）
    2. 严格 dispatcher 模式匹配（高精度，召回略低）
    取并集。
    """
    selectors = set()

    # 方法 1: 扫所有 PUSH4
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        if op == 0x63 and i + 4 < len(bytecode):  # PUSH4
            sel = bytecode[i+1:i+5]
            # 过滤掉明显不是选择器的（全 0、全 F、错误码常量等）
            if sel not in (b'\x00'*4, b'\xff'*4) and sel != b'\x08\xc3\x79\xa0':
                selectors.add("0x" + sel.hex())
            i += 5
        elif 0x60 <= op <= 0x7f:  # PUSH1 ~ PUSH32
            i += (op - 0x5f) + 1
        else:
            i += 1

    # 方法 2: 严格 dispatcher 模式
    # 标准模式 1: DUP1 PUSH4 <sel> EQ PUSH2 <dest> JUMPI
    pattern1 = re.compile(rb'\x80\x63(.{4})\x14\x61.{2}\x57', re.DOTALL)
    # 标准模式 2: DUP1 PUSH4 <sel> EQ PUSH3 <dest> JUMPI（合约较大时）
    pattern2 = re.compile(rb'\x80\x63(.{4})\x14\x62.{3}\x57', re.DOTALL)

    dispatcher_sels = set()
    for pat in (pattern1, pattern2):
        for m in pat.finditer(bytecode):
            dispatcher_sels.add("0x" + m.group(1).hex())

    # dispatcher 里发现的选择器是高置信度的
    return selectors, dispatcher_sels


# ============================================================================
# 模块 3：函数名反查（多源）
# ============================================================================
_lookup_cache = {}

def lookup_signature(selector: str) -> list:
    """从 4byte + Openchain + 内置字典反查函数签名"""
    if selector in _lookup_cache:
        return _lookup_cache[selector]

    sigs = []

    # 内置字典优先（最快、最可信）
    if selector in BUILTIN_DICT:
        sigs.append(BUILTIN_DICT[selector])

    # 4byte.directory
    try:
        r = requests.get(
            f"https://www.4byte.directory/api/v1/signatures/?hex_signature={selector}",
            timeout=8
        )
        if r.status_code == 200:
            for x in r.json().get("results", [])[:5]:
                sig = x.get("text_signature", "")
                if sig and sig not in sigs:
                    sigs.append(sig)
    except Exception:
        pass

    # Openchain (sig.eth.samczsun.com)
    try:
        r = requests.get(
            f"https://api.openchain.xyz/signature-database/v1/lookup?function={selector}",
            timeout=8
        )
        if r.status_code == 200:
            data = r.json().get("result", {}).get("function", {}).get(selector, [])
            for x in data[:5]:
                sig = x.get("name", "")
                if sig and sig not in sigs:
                    sigs.append(sig)
    except Exception:
        pass

    _lookup_cache[selector] = sigs
    return sigs


# ============================================================================
# 模块 4：危险等级评估
# ============================================================================
def assess_danger(signatures: list) -> str:
    """根据函数名匹配高危关键词"""
    if not signatures:
        return "UNKNOWN"

    all_names = " ".join(signatures).lower()

    for level in ("RED", "ORANGE", "YELLOW", "GREEN"):
        for kw in DANGER_KEYWORDS[level]:
            if kw.lower() in all_names:
                return level
    return "UNKNOWN"


# ============================================================================
# 模块 5：静态调用探测
# ============================================================================
def probe_function(w3: Web3, addr: str, selector: str) -> tuple:
    """
    用 staticcall 探测函数性质。
    返回 (描述字符串, 是否疑似 view)
    """
    addr = Web3.to_checksum_address(addr)
    try:
        result = w3.eth.call({"to": addr, "data": selector})
        if result == b'' or result == b'\x00' * 32:
            return ("✅ 调用成功（返回空，可能是 view 但没数据）", True)
        return (f"✅ 调用成功，返回 {len(result)} 字节: {result.hex()[:64]}...", True)
    except Exception as e:
        msg = str(e).lower()
        if "out of gas" in msg or "ran out" in msg:
            return ("💥 写函数（被权限/状态检查 revert，gas 用完）", False)
        elif "revert" in msg:
            # 尝试解析 revert reason
            reason = ""
            err_str = str(e)
            m = re.search(r"reverted: (.+?)(?:\"|$|,)", err_str)
            if m:
                reason = f"  原因: {m.group(1)}"
            return (f"⚠️  revert（需要参数 / 权限不足 / 状态不对）{reason}", False)
        return (f"❓ 错误: {str(e)[:80]}", False)


# ============================================================================
# 模块 6：历史 calldata 抓样
# ============================================================================
def fetch_recent_calldata_samples(addr: str, scanner_url: str, api_key: str = "") -> dict:
    """
    从 Etherscan/Arbiscan 风格 API 拉最近 100 笔交易，按选择器分组。
    返回 {selector: [calldata_sample, ...]}
    """
    samples = {}
    try:
        url = (f"{scanner_url}?module=account&action=txlist"
               f"&address={addr}&startblock=0&endblock=99999999"
               f"&page=1&offset=100&sort=desc")
        if api_key:
            url += f"&apikey={api_key}"

        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return samples

        data = r.json()
        if data.get("status") != "1":
            return samples

        for tx in data.get("result", []):
            inp = tx.get("input", "")
            if len(inp) >= 10:
                sel = inp[:10].lower()
                samples.setdefault(sel, []).append(inp)
    except Exception:
        pass
    return samples


# ============================================================================
# 模块 7：从字节码提取明文字符串（错误信息等）
# ============================================================================
def extract_strings(bytecode: bytes, min_len: int = 4) -> list:
    """提取字节码中的可见 ASCII 字符串"""
    strings = []
    current = b""
    for b in bytecode:
        if 32 <= b < 127:  # 可见 ASCII
            current += bytes([b])
        else:
            if len(current) >= min_len:
                try:
                    s = current.decode("ascii")
                    # 过滤太机械的、看着像噪音的
                    if any(c.isalpha() for c in s):
                        strings.append(s)
                except Exception:
                    pass
            current = b""
    return list(set(strings))[:30]  # 去重，最多 30 条


# ============================================================================
# 模块 8：主流程
# ============================================================================
def analyze_contract(addr: str, w3: Web3, scanner_url: Optional[str] = None,
                     api_key: str = "", deep_probe: bool = True) -> dict:
    addr = Web3.to_checksum_address(addr)

    console.print(f"\n[bold cyan]╔══════════════════════════════════════════╗[/bold cyan]" if HAS_RICH else "")
    console.print(f"[bold cyan]║  开始分析合约: {addr}  ║[/bold cyan]" if HAS_RICH else f"分析合约: {addr}")
    console.print(f"[bold cyan]╚══════════════════════════════════════════╝[/bold cyan]\n" if HAS_RICH else "")

    # 1. 拉字节码
    code = fetch_bytecode(w3, addr)
    if not code or len(code) == 0:
        console.print("[red]❌ 这不是合约（EOA / 未部署 / 已自毁）[/red]" if HAS_RICH else "不是合约")
        return {"error": "not a contract"}

    console.print(f"📦 字节码大小: [bold]{len(code)}[/bold] 字节")

    # 2. 代理检测
    proxy_info = detect_proxy(w3, addr)
    if proxy_info["is_proxy"]:
        console.print(f"🔗 [yellow]检测到代理合约[/yellow]")
        console.print(f"   实现合约: [cyan]{proxy_info['impl']}[/cyan]")
        if proxy_info["admin"]:
            console.print(f"   代理 admin: {proxy_info['admin']}")
        if proxy_info["beacon"]:
            console.print(f"   beacon: {proxy_info['beacon']}")

    # 3. 收集所有要扫的字节码（代理 + 实现）
    bytecodes = {addr: code}
    if proxy_info.get("impl"):
        impl_code = fetch_bytecode(w3, proxy_info["impl"])
        if impl_code:
            bytecodes[proxy_info["impl"]] = impl_code

    # 4. 提取选择器
    all_selectors = set()
    high_conf_selectors = set()
    for c in bytecodes.values():
        push4_set, dispatcher_set = extract_selectors(c)
        all_selectors |= push4_set
        high_conf_selectors |= dispatcher_set

    console.print(f"🔍 扫描出选择器: 共 [bold]{len(all_selectors)}[/bold] 个候选, "
                  f"其中 [bold green]{len(high_conf_selectors)}[/bold green] 个高置信度（dispatcher 模式）\n")

    # 5. 对每个选择器：反查 + 评估 + 探测
    functions = []
    print_progress = lambda i, n: console.print(f"  [{i+1}/{n}] 处理中...", end="\r") if HAS_RICH else None

    selectors_to_process = sorted(all_selectors)
    for idx, sel in enumerate(selectors_to_process):
        is_high_conf = sel in high_conf_selectors
        sigs = lookup_signature(sel)
        danger = assess_danger(sigs)

        info = FunctionInfo(
            selector=sel,
            signatures=sigs,
            danger_level=danger,
        )
        if not is_high_conf:
            info.notes.append("低置信度（PUSH4 扫描，可能不是真函数）")

        if deep_probe:
            result, is_view = probe_function(w3, addr, sel)
            info.static_call_result = result
            info.likely_view = is_view

        functions.append(info)

        # 限制 API 速率
        if idx % 10 == 9:
            time.sleep(0.5)

    # 6. 提取字符串（找错误信息）
    all_strings = []
    for c in bytecodes.values():
        all_strings.extend(extract_strings(c))
    interesting_strings = [s for s in set(all_strings) if any(
        kw in s.lower() for kw in ["owner", "admin", "auth", "permit", "valid",
                                    "amount", "balance", "fail", "error", "must"]
    )][:15]

    # 7. 历史 calldata（如果给了 scanner）
    calldata_samples = {}
    if scanner_url:
        console.print("\n📜 拉取历史交易样本...")
        calldata_samples = fetch_recent_calldata_samples(addr, scanner_url, api_key)

    # 8. 构建报告
    report = {
        "address": addr,
        "bytecode_size": len(code),
        "proxy": proxy_info,
        "total_selectors": len(all_selectors),
        "high_conf_selectors": len(high_conf_selectors),
        "functions": [asdict(f) for f in functions],
        "interesting_strings": interesting_strings,
        "calldata_samples_count": {sel: len(s) for sel, s in calldata_samples.items()},
    }

    return report


# ============================================================================
# 模块 9：报告打印
# ============================================================================
DANGER_COLORS = {"RED": "red", "ORANGE": "yellow", "YELLOW": "yellow",
                 "GREEN": "green", "UNKNOWN": "white"}
DANGER_ICONS = {"RED": "🔴", "ORANGE": "🟠", "YELLOW": "🟡",
                "GREEN": "🟢", "UNKNOWN": "⚪"}

def print_report(report: dict):
    if "error" in report:
        return

    console.print("\n[bold]═══ 函数清单 ═══[/bold]\n" if HAS_RICH else "\n=== 函数清单 ===\n")

    if HAS_RICH:
        table = Table(box=box.ROUNDED, show_lines=False)
        table.add_column("等级", width=6, justify="center")
        table.add_column("选择器", width=12)
        table.add_column("函数签名", width=50)
        table.add_column("静态调用结果", width=45)

        # 按危险等级排序：红 > 橙 > 黄 > 未知 > 绿
        order = {"RED": 0, "ORANGE": 1, "YELLOW": 2, "UNKNOWN": 3, "GREEN": 4}
        sorted_funcs = sorted(report["functions"], key=lambda f: (order.get(f["danger_level"], 5), f["selector"]))

        for f in sorted_funcs:
            level = f["danger_level"]
            icon = DANGER_ICONS[level]
            color = DANGER_COLORS[level]
            sigs = " | ".join(f["signatures"][:2]) if f["signatures"] else "[grey50]【未知】[/grey50]"
            result = f["static_call_result"][:42] if f["static_call_result"] else "—"

            table.add_row(
                f"{icon}",
                f"[{color}]{f['selector']}[/{color}]",
                sigs,
                result,
            )
        console.print(table)
    else:
        order = {"RED": 0, "ORANGE": 1, "YELLOW": 2, "UNKNOWN": 3, "GREEN": 4}
        sorted_funcs = sorted(report["functions"], key=lambda f: (order.get(f["danger_level"], 5), f["selector"]))
        for f in sorted_funcs:
            sigs = " | ".join(f["signatures"][:2]) if f["signatures"] else "【未知】"
            print(f"  {DANGER_ICONS[f['danger_level']]} {f['selector']}  {sigs}")
            print(f"        {f['static_call_result']}")
            print()

    # 统计
    counts = {}
    for f in report["functions"]:
        counts[f["danger_level"]] = counts.get(f["danger_level"], 0) + 1

    console.print("\n[bold]═══ 风险概览 ═══[/bold]\n" if HAS_RICH else "\n=== 风险概览 ===\n")
    for level in ("RED", "ORANGE", "YELLOW", "UNKNOWN", "GREEN"):
        if counts.get(level, 0) > 0:
            console.print(f"  {DANGER_ICONS[level]}  {level:8s}: [bold]{counts[level]}[/bold] 个函数")

    # 关键字符串
    if report.get("interesting_strings"):
        console.print("\n[bold]═══ 字节码中的可见字符串 ═══[/bold]\n" if HAS_RICH else "\n=== 字节码中的字符串 ===\n")
        for s in report["interesting_strings"]:
            console.print(f"  • {s}")

    # 总结建议
    console.print("\n[bold cyan]═══ 安全建议 ═══[/bold cyan]\n" if HAS_RICH else "\n=== 安全建议 ===\n")
    red_funcs = [f for f in report["functions"] if f["danger_level"] == "RED"]
    orange_funcs = [f for f in report["functions"] if f["danger_level"] == "ORANGE"]

    if red_funcs:
        console.print(f"  🔴 [red]发现 {len(red_funcs)} 个高危资金类函数[/red]，"
                      f"务必确认它们都有 onlyOwner / onlyRole 等访问控制：")
        for f in red_funcs[:5]:
            sigs = " | ".join(f["signatures"][:1]) if f["signatures"] else "【未知】"
            console.print(f"     - {f['selector']}  {sigs}")

    if orange_funcs:
        console.print(f"  🟠 [yellow]发现 {len(orange_funcs)} 个权限管理类函数[/yellow]，"
                      f"建议这些函数由多签 + Timelock 控制：")
        for f in orange_funcs[:5]:
            sigs = " | ".join(f["signatures"][:1]) if f["signatures"] else "【未知】"
            console.print(f"     - {f['selector']}  {sigs}")

    if report["proxy"]["is_proxy"]:
        console.print(f"  🔗 这是代理合约，实现合约可被升级。请确认 ProxyAdmin "
                      f"({report['proxy'].get('admin') or '未设置'}) 不是单 EOA。")


# ============================================================================
# CLI 入口
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="EVM 合约函数侦察工具")
    parser.add_argument("address", help="要分析的合约地址")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help=f"RPC URL (默认: {DEFAULT_RPC})")
    parser.add_argument("--scanner", default="https://api.arbiscan.io/api",
                        help="区块浏览器 API（用来抓历史交易样本）")
    parser.add_argument("--api-key", default="", help="区块浏览器 API key（可选）")
    parser.add_argument("--out", default=None, help="把完整 JSON 报告写到文件")
    parser.add_argument("--no-probe", action="store_true",
                        help="跳过静态调用探测（快但信息少）")
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        console.print(f"[red]❌ 无法连接到 RPC: {args.rpc}[/red]" if HAS_RICH
                      else f"无法连接到 RPC: {args.rpc}")
        sys.exit(1)

    chain_id = w3.eth.chain_id
    console.print(f"🌐 已连接到链 ID: [bold]{chain_id}[/bold]")

    report = analyze_contract(
        args.address, w3,
        scanner_url=args.scanner,
        api_key=args.api_key,
        deep_probe=not args.no_probe,
    )

    print_report(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"\n📝 完整报告已写入: [green]{args.out}[/green]")


if __name__ == "__main__":
    main()
