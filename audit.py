#!/usr/bin/env python3
"""
audit.py —— EVM 合约批量审计一条龙工具
=========================================

✨ 特性：
  • 单文件自包含 —— 一个 audit.py 搞定所有，不依赖其他 py
  • 自定义 RPC —— 完全自由的 RPC 参数（--rpc）+ 多链预设（--chain）
  • 批量检测 —— 单个 / 多个 / 文件 / stdin 多种输入方式
  • 一条龙审计 —— 字节码 + 代理 + 选择器 + 反查 + 危险评估 + 碰撞检测 +
                  静态调用 + 字符串 + 关键状态 + 综合风险评分（0-100）
  • 多种输出 —— 控制台漂亮表格 + JSON + CSV
  • 并发处理 —— 多线程加速批量审计

⚠️  只读、只做侦察。本工具不发任何交易、不需要私钥。

依赖：pip install web3 requests rich

================== 用法 ==================

# 单个合约
python audit.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559

# 多个合约
python audit.py 0xAddr1 0xAddr2 0xAddr3

# 自定义 RPC
python audit.py 0xAddr --rpc https://my-private-rpc.io

# 多链预设
python audit.py 0xAddr --chain arb        # arb, eth, op, base, bsc, polygon, ...
python audit.py 0xAddr --chain local      # 本地 Anvil/Hardhat

# 批量从文件
python audit.py --file addresses.txt --workers 5

# 输出 JSON / CSV
python audit.py --file addrs.txt --json report.json --csv summary.csv

# stdin 输入（管道）
cat addresses.txt | python audit.py --stdin --chain arb

# 只看高危合约
python audit.py --file addrs.txt --min-risk 50

# 完整深度模式（含静态调用 + 字符串提取 + 关键状态）
python audit.py 0xAddr --deep
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests
from web3 import Web3

# rich 用于美化输出（没装也能跑）
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw):
            # 简单去除 rich 标记
            txt = " ".join(str(x) for x in a)
            txt = re.sub(r"\[/?[a-z0-9 _#]+\]", "", txt)
            print(txt)
    console = _C()


# ==============================================================================
# 配置
# ==============================================================================
# 多链 RPC 预设（你也可以用 --rpc 完全自定义）
CHAINS = {
    "eth":      "https://eth.llamarpc.com",
    "arb":      "https://arb1.arbitrum.io/rpc",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "op":       "https://mainnet.optimism.io",
    "base":     "https://mainnet.base.org",
    "bsc":      "https://bsc-dataseed.binance.org",
    "polygon":  "https://polygon-rpc.com",
    "avax":     "https://api.avax.network/ext/bc/C/rpc",
    "scroll":   "https://rpc.scroll.io",
    "linea":    "https://rpc.linea.build",
    "blast":    "https://rpc.blast.io",
    "mantle":   "https://rpc.mantle.xyz",
    "celo":     "https://forno.celo.org",
    "sepolia":  "https://sepolia.gateway.tenderly.co",
    "holesky":  "https://ethereum-holesky.publicnode.com",
    # 本地节点
    "local":    "http://127.0.0.1:8545",
    "anvil":    "http://127.0.0.1:8545",
    "hardhat":  "http://127.0.0.1:8545",
}

# EIP-1967 代理槽位
EIP1967_IMPL_SLOT   = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
EIP1967_ADMIN_SLOT  = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
EIP1967_BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50

# 危险关键词
DANGER_KEYWORDS = {
    "RED": [   # 直接搬钱
        "withdraw", "drain", "sweep", "rescue", "recover", "emergency",
        "selfdestruct", "kill", "destruct", "destroy",
        "skim", "collect", "harvest", "claim", "redeem", "exit",
    ],
    "ORANGE": [  # 改变权限
        "transferOwnership", "setOwner", "setAdmin", "addAdmin", "removeAdmin",
        "grantRole", "revokeRole", "renounceOwnership", "renounceRole",
        "upgrade", "upgradeTo", "setImplementation", "changeImpl",
        "initialize", "init", "setUp", "setup",
        "setMinter", "setManager", "setOperator", "setController",
        "setGovernance", "setTreasury",
    ],
    "YELLOW": [  # 改变状态
        "mint", "burn", "pause", "unpause", "freeze",
        "setFee", "setRate", "setPair", "setRouter", "setOracle",
        "setWhitelist", "addToWhitelist", "blacklist",
        "transfer", "approve", "transferFrom",
    ],
    "GREEN": [   # 只读
        "owner", "admin", "balanceOf", "totalSupply", "name", "symbol",
        "decimals", "allowance", "implementation", "paused",
    ],
}

# 内置高频函数字典（4byte 不可达时保底）
BUILTIN_DICT = {
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
    "0x8da5cb5b": "owner()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
    "0xf851a440": "admin()",
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
    "0x5c975abb": "paused()",
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
    "0x9d76ea58": "factory()",
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1ef286": "upgradeToAndCall(address,bytes)",
    "0x5c60da1b": "implementation()",
    "0x91d14854": "hasRole(bytes32,address)",
    "0x2f2ff15d": "grantRole(bytes32,address)",
    "0xd547741f": "revokeRole(bytes32,address)",
    "0x8129fc1c": "initialize()",
    "0xc4d66de8": "initialize(address)",
}

# 业务关键词（用于识别"真函数")
BUSINESS_KEYWORDS = [
    "transfer", "approve", "mint", "burn", "withdraw", "deposit",
    "swap", "claim", "stake", "unstake", "harvest", "exit",
    "balance", "supply", "owner", "admin", "name", "symbol",
    "factory", "pair", "router", "oracle", "vault", "pool",
    "permit", "delegate", "vote", "propose",
]


# ==============================================================================
# 字节码 + 代理检测
# ==============================================================================
def fetch_bytecode(w3, addr):
    """拉取 runtime 字节码"""
    return w3.eth.get_code(Web3.to_checksum_address(addr))


def detect_proxy(w3, addr):
    """检测 EIP-1967 代理"""
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


# ==============================================================================
# 选择器提取
# ==============================================================================
def extract_selectors(bytecode):
    """从字节码提取所有函数选择器（PUSH4 + dispatcher 模式）"""
    bytecode = bytes(bytecode)
    selectors = set()
    dispatcher = set()

    # 方法 1: 全字节码 PUSH4 扫描
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        if op == 0x63 and i + 4 < len(bytecode):  # PUSH4
            sel = bytecode[i+1:i+5]
            if sel not in (b'\x00'*4, b'\xff'*4) and sel != b'\x08\xc3\x79\xa0':
                selectors.add("0x" + sel.hex())
            i += 5
        elif 0x60 <= op <= 0x7f:  # PUSH1~PUSH32
            i += (op - 0x5f) + 1
        else:
            i += 1

    # 方法 2: 严格 dispatcher 模式
    pat1 = re.compile(rb'\x80\x63(.{4})\x14\x61.{2}\x57', re.DOTALL)
    pat2 = re.compile(rb'\x80\x63(.{4})\x14\x62.{3}\x57', re.DOTALL)
    for pat in (pat1, pat2):
        for m in pat.finditer(bytecode):
            dispatcher.add("0x" + m.group(1).hex())

    return selectors, dispatcher


# ==============================================================================
# 函数名反查（多源）
# ==============================================================================
_lookup_cache = {}


def lookup_signature(selector):
    """从内置字典 + 4byte + Openchain 反查"""
    if selector in _lookup_cache:
        return _lookup_cache[selector]

    sigs = []
    if selector in BUILTIN_DICT:
        sigs.append(BUILTIN_DICT[selector])

    # Openchain（更可靠）
    try:
        r = requests.get(
            f"https://api.openchain.xyz/signature-database/v1/lookup?function={selector}",
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json().get("result", {}).get("function", {}).get(selector, [])
            for x in data[:5]:
                sig = x.get("name", "")
                if sig and sig not in sigs:
                    sigs.append(sig)
    except Exception:
        pass

    # 4byte.directory（备用）
    try:
        r = requests.get(
            f"https://www.4byte.directory/api/v1/signatures/?hex_signature={selector}",
            timeout=5,
        )
        if r.status_code == 200:
            for x in r.json().get("results", [])[:5]:
                sig = x.get("text_signature", "")
                if sig and sig not in sigs:
                    sigs.append(sig)
    except Exception:
        pass

    _lookup_cache[selector] = sigs
    return sigs


# ==============================================================================
# 签名分类（区分真实 vs 爆破生成的垃圾签名）
# ==============================================================================
def classify_signature(sig):
    """分类: 'real' | 'garbage' | 'neutral'"""
    if not sig:
        return "neutral"

    name = sig.split("(")[0]

    # 1. 占位名字
    if re.match(r"^func_\d+", sig) or re.match(r"^Unresolved_", sig):
        return "garbage"

    # 2. 名字异常
    if len(name) < 3 or len(name) > 35:
        return "garbage"

    # 3. CamelCase 4+ 段
    cc = re.findall(r"[A-Z][a-z]+", name)
    if len(cc) >= 4:
        legit = {"transferFromAndCall", "safeTransferFrom", "increaseAllowance",
                 "decreaseAllowance", "permitForAll", "supportsInterface",
                 "tokenOfOwnerByIndex", "isApprovedForAll", "setApprovalForAll"}
        if name not in legit:
            return "garbage"

    # 4. 单字节参数（爆破特征）
    if re.search(r"\((bytes1|bytes2)\)", sig):
        return "garbage"

    # 5. 多数组参数（爆破特征）
    params = sig[sig.find("(")+1:sig.rfind(")")] if "(" in sig else ""
    if params.count("[") >= 3:
        return "garbage"

    # 6. 下划线分隔多 token（hashbreaker）
    if name.count("_") >= 3:
        return "garbage"

    # 7. 连续数字 5+
    if re.search(r"\d{5,}", name):
        return "garbage"

    # 8. hex 后缀
    if re.search(r"[_x][0-9a-f]{6,}", name.lower()):
        return "garbage"

    # 业务关键字命中 → 真函数
    for kw in BUSINESS_KEYWORDS:
        if kw in sig.lower():
            return "real"
    return "neutral"


def filter_signatures(sigs):
    """分离 real / garbage"""
    real, garbage = [], []
    for s in sigs:
        if classify_signature(s) == "garbage":
            garbage.append(s)
        else:
            real.append(s)
    return real, garbage


# ==============================================================================
# 危险等级评估
# ==============================================================================
def assess_danger(signatures):
    """根据函数名匹配高危关键词"""
    if not signatures:
        return "UNKNOWN"

    real_sigs, _ = filter_signatures(signatures)
    if not real_sigs:
        return "UNKNOWN"

    text = " ".join(real_sigs).lower()
    for level in ("RED", "ORANGE", "YELLOW", "GREEN"):
        for kw in DANGER_KEYWORDS[level]:
            if kw.lower() in text:
                return level
    return "UNKNOWN"


# ==============================================================================
# 选择器碰撞检测
# ==============================================================================
def detect_dict_collisions(functions):
    """字典碰撞（多个真实签名共享同一选择器 / 字典污染）"""
    warnings = []
    for f in functions:
        sigs = f["signatures"]
        if len(sigs) < 2:
            continue
        real_count = sum(1 for s in sigs if classify_signature(s) == "real")
        garbage_count = sum(1 for s in sigs if classify_signature(s) == "garbage")
        if real_count >= 2:
            warnings.append({
                "selector": f["selector"], "level": "HIGH", "type": "DICT_COLLISION",
                "message": f"对应 {real_count} 个真实签名，需结合字节码确认",
            })
        elif garbage_count >= 1 and real_count >= 1:
            warnings.append({
                "selector": f["selector"], "level": "MEDIUM", "type": "DICT_NOISE",
                "message": f"4byte 字典包含 {garbage_count} 个爆破垃圾签名",
            })
    return warnings


def detect_proxy_collisions(proxy_dispatcher, impl_dispatcher):
    """代理↔实现选择器冲突（Audius-style 漏洞前置条件）"""
    if not proxy_dispatcher or not impl_dispatcher:
        return []
    overlap = proxy_dispatcher & impl_dispatcher
    return [{
        "selector": s, "level": "CRITICAL", "type": "PROXY_COLLISION",
        "message": "代理↔实现共享此选择器，可能存在 Audius-style 漏洞",
    } for s in overlap]


# ==============================================================================
# 静态调用探测
# ==============================================================================
def probe_function(w3, addr, selector):
    """eth_call 探测函数性质"""
    try:
        result = w3.eth.call({"to": Web3.to_checksum_address(addr), "data": selector})
        if result == b'' or result == b'\x00' * 32:
            return "view (空返回)", True, result
        return f"view (返回 {len(result)} 字节)", True, result
    except Exception as e:
        msg = str(e).lower()
        if "out of gas" in msg or "ran out" in msg:
            return "写函数 (gas 用完)", False, None
        elif "revert" in msg:
            return "revert (需参数/权限)", False, None
        return "未知错误", False, None


# ==============================================================================
# 字符串提取
# ==============================================================================
def extract_strings(bytecode, min_len=4):
    """提取字节码中的可读 ASCII 字符串"""
    strings = []
    cur = b""
    for b in bytecode:
        if 32 <= b < 127:
            cur += bytes([b])
        else:
            if len(cur) >= min_len:
                try:
                    s = cur.decode("ascii")
                    if any(c.isalpha() for c in s):
                        strings.append(s)
                except Exception:
                    pass
            cur = b""
    return list(set(strings))


def filter_interesting_strings(strings):
    """过滤出有意义的字符串"""
    keywords = ["owner", "admin", "auth", "permit", "valid", "amount",
                "balance", "fail", "error", "must", "require", "only",
                "paus", "freeze", "blacklist", "withdraw", "transfer",
                "exceed", "underflow", "overflow", "denied"]
    return sorted([s for s in strings
                   if any(kw in s.lower() for kw in keywords)
                   and 4 <= len(s) <= 80])[:20]


# ==============================================================================
# 关键状态读取（admin/owner 等）
# ==============================================================================
def read_key_state(w3, addr):
    """尝试调用 admin() / owner() / implementation() 等读取关键状态"""
    state = {}
    addr_cs = Web3.to_checksum_address(addr)

    probes = [
        ("admin",          "0xf851a440", "address"),
        ("owner",          "0x8da5cb5b", "address"),
        ("implementation", "0x5c60da1b", "address"),
        ("paused",         "0x5c975abb", "bool"),
        ("name",           "0x06fdde03", "string"),
        ("symbol",         "0x95d89b41", "string"),
        ("decimals",       "0x313ce567", "uint8"),
        ("totalSupply",    "0x18160ddd", "uint256"),
    ]

    for key, selector, ret_type in probes:
        try:
            raw = w3.eth.call({"to": addr_cs, "data": selector})
            if not raw or len(raw) < 32:
                continue
            if ret_type == "address":
                a = "0x" + raw.hex()[-40:]
                if int(a, 16) != 0:
                    state[key] = Web3.to_checksum_address(a)
            elif ret_type == "bool":
                state[key] = (raw[-1] == 1)
            elif ret_type in ("uint8", "uint256"):
                state[key] = int.from_bytes(raw, "big")
            elif ret_type == "string":
                # ABI string: offset(32) + length(32) + data
                if len(raw) >= 96:
                    length = int.from_bytes(raw[32:64], "big")
                    if 0 < length <= 200:
                        state[key] = raw[64:64+length].decode("utf-8", errors="replace")
        except Exception:
            pass

    return state


def is_eoa(w3, addr):
    """判断地址是 EOA 还是合约"""
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(addr))
        return len(code) == 0
    except Exception:
        return None


# ==============================================================================
# 综合风险评分（核心）
# ==============================================================================
def calculate_risk_score(report):
    """
    计算综合风险评分 0-100

    评分维度：
    + 是否代理 + ProxyAdmin 是 EOA   → 重点关注
    + RED/ORANGE/YELLOW 函数数量    → 累加
    + 选择器碰撞（CRITICAL/HIGH）   → 重点关注
    + admin/owner 是否单 EOA        → 重点关注
    + 字节码大小异常                → 提示
    """
    score = 0
    reasons = []

    # 不是合约直接 0
    if report.get("error") or report["bytecode_size"] == 0:
        return 0, ["非合约/已自毁"]

    # 字节码大小（minimal proxy / 极小合约可能是诱饵）
    if report["bytecode_size"] < 1000:
        score += 5
        reasons.append(f"字节码较小（{report['bytecode_size']} 字节）")

    # 代理风险
    proxy = report.get("proxy", {})
    if proxy.get("is_proxy"):
        score += 10
        reasons.append("代理合约（implementation 可升级）")
        proxy_admin = proxy.get("admin")
        if proxy_admin and report.get("proxy_admin_is_eoa"):
            score += 25
            reasons.append(f"⚠️ ProxyAdmin 是 EOA: {proxy_admin}")

    # 函数等级
    counts = report["danger_counts"]
    score += counts.get("RED", 0) * 12
    score += counts.get("ORANGE", 0) * 5
    score += counts.get("YELLOW", 0) * 1
    if counts.get("RED", 0) >= 1:
        reasons.append(f"含 {counts['RED']} 个高危资金类函数")
    if counts.get("ORANGE", 0) >= 1:
        reasons.append(f"含 {counts['ORANGE']} 个权限管理类函数")

    # 选择器碰撞
    coll = report.get("collisions", {})
    proxy_col = coll.get("proxy", [])
    dict_col = coll.get("dict", [])
    if proxy_col:
        score += 50 * len(proxy_col)
        reasons.append(f"🚨 代理↔实现 {len(proxy_col)} 个选择器冲突 (Audius 风险)")
    if any(w["level"] == "HIGH" for w in dict_col):
        score += 8
        reasons.append("字典存在多真实签名碰撞")

    # 关键状态
    state = report.get("state", {})
    admin = state.get("admin")
    if admin:
        if admin == "0x0000000000000000000000000000000000000000":
            score -= 15
            reasons.append("admin 已清零")
        elif report.get("admin_is_eoa"):
            score += 25
            reasons.append(f"⚠️ admin 是 EOA: {admin}")
        else:
            reasons.append(f"admin 是合约 (可能多签): {admin}")

    owner = state.get("owner")
    if owner:
        if owner == "0x0000000000000000000000000000000000000000":
            score -= 10
            reasons.append("owner 已 renounce")
        elif report.get("owner_is_eoa"):
            score += 20
            reasons.append(f"⚠️ owner 是 EOA: {owner}")
        else:
            reasons.append(f"owner 是合约: {owner}")

    return max(0, min(100, score)), reasons


def risk_level(score):
    if score < 21:
        return "LOW", "green"
    elif score < 41:
        return "MEDIUM", "yellow"
    elif score < 66:
        return "HIGH", "orange1"
    else:
        return "CRITICAL", "red"


# ==============================================================================
# 单合约审计（核心一条龙函数）
# ==============================================================================
def audit_contract(w3, addr, deep=False, lookup=True):
    """对单个合约做完整审计，返回 dict"""
    addr = Web3.to_checksum_address(addr)
    report = {
        "address": addr,
        "chain_id": w3.eth.chain_id,
        "bytecode_size": 0,
        "proxy": {"is_proxy": False, "impl": None, "admin": None, "beacon": None},
        "selectors": [],
        "functions": [],          # [{selector, signatures, danger, real_sigs, garbage_sigs, ...}]
        "danger_counts": {},
        "collisions": {"proxy": [], "dict": []},
        "interesting_strings": [],
        "state": {},
        "admin_is_eoa": None,
        "owner_is_eoa": None,
        "proxy_admin_is_eoa": None,
        "risk_score": 0,
        "risk_level": "LOW",
        "risk_reasons": [],
        "audited_at": int(time.time()),
    }

    # 1. 字节码
    try:
        code = fetch_bytecode(w3, addr)
    except Exception as e:
        report["error"] = f"获取字节码失败: {e}"
        return report

    if not code or len(code) == 0:
        report["error"] = "非合约地址 (EOA / 未部署 / 已自毁)"
        return report

    report["bytecode_size"] = len(code)

    # 2. 代理检测
    try:
        report["proxy"] = detect_proxy(w3, addr)
    except Exception:
        pass

    # 3. 选择器提取（含实现合约）
    proxy_disp, impl_disp = set(), set()
    try:
        proxy_sels, proxy_disp = extract_selectors(code)
        all_selectors = proxy_sels.copy()
        all_dispatcher = proxy_disp.copy()

        if report["proxy"]["impl"]:
            try:
                impl_code = fetch_bytecode(w3, report["proxy"]["impl"])
                if impl_code:
                    impl_sels, impl_disp = extract_selectors(impl_code)
                    all_selectors |= impl_sels
                    all_dispatcher |= impl_disp
            except Exception:
                pass

        report["selectors"] = sorted(all_selectors)
    except Exception as e:
        report["error"] = f"提取选择器失败: {e}"
        return report

    # 4. 函数名反查 + 危险等级
    danger_counts = {"RED": 0, "ORANGE": 0, "YELLOW": 0, "GREEN": 0, "UNKNOWN": 0}
    functions = []
    for sel in sorted(all_selectors):
        sigs = lookup_signature(sel) if lookup else []
        danger = assess_danger(sigs)
        real_sigs, garbage_sigs = filter_signatures(sigs)
        functions.append({
            "selector": sel,
            "signatures": sigs,
            "real_signatures": real_sigs,
            "garbage_signatures": garbage_sigs,
            "danger": danger,
            "is_dispatcher": sel in all_dispatcher,
        })
        danger_counts[danger] = danger_counts.get(danger, 0) + 1

    report["functions"] = functions
    report["danger_counts"] = danger_counts

    # 5. 选择器碰撞检测
    report["collisions"]["dict"] = detect_dict_collisions(functions)
    report["collisions"]["proxy"] = detect_proxy_collisions(proxy_disp, impl_disp)

    # 6. 深度模式：字符串提取 + 关键状态
    if deep:
        try:
            all_strs = extract_strings(code)
            if report["proxy"]["impl"]:
                try:
                    impl_code = fetch_bytecode(w3, report["proxy"]["impl"])
                    all_strs += extract_strings(impl_code)
                except Exception:
                    pass
            report["interesting_strings"] = filter_interesting_strings(set(all_strs))
        except Exception:
            pass

        # 关键状态
        try:
            state = read_key_state(w3, addr)
            report["state"] = state
            if state.get("admin"):
                report["admin_is_eoa"] = is_eoa(w3, state["admin"])
            if state.get("owner"):
                report["owner_is_eoa"] = is_eoa(w3, state["owner"])
        except Exception:
            pass

        # ProxyAdmin
        if report["proxy"]["admin"]:
            report["proxy_admin_is_eoa"] = is_eoa(w3, report["proxy"]["admin"])

    # 7. 综合风险评分
    score, reasons = calculate_risk_score(report)
    report["risk_score"] = score
    report["risk_level"] = risk_level(score)[0]
    report["risk_reasons"] = reasons

    return report


# ==============================================================================
# 输出格式化
# ==============================================================================
def short_addr(addr, n=6):
    if not addr:
        return "—"
    return f"{addr[:2+n]}…{addr[-4:]}"


def print_report(report):
    """漂亮打印单个合约的审计报告"""
    if "error" in report and not report.get("bytecode_size"):
        console.print(f"\n[red]❌ {report['address']}: {report['error']}[/red]" if HAS_RICH
                      else f"❌ {report['address']}: {report['error']}")
        return

    addr = report["address"]
    score = report["risk_score"]
    level, color = risk_level(score)

    # 标题面板
    icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}[level]
    title = f"{icon} {addr}  ·  评分 {score}/100  ·  等级 {level}"
    if HAS_RICH:
        console.print(Panel(title, style=color, expand=False))
    else:
        print(f"\n=== {title} ===")

    # 基础信息
    if HAS_RICH:
        info = Table(box=box.SIMPLE, show_header=False)
        info.add_column("字段", style="cyan", width=14)
        info.add_column("值")
        info.add_row("字节码大小", f"{report['bytecode_size']:,} 字节")
        info.add_row("Chain ID",  str(report["chain_id"]))
        proxy = report["proxy"]
        if proxy["is_proxy"]:
            info.add_row("代理类型", "EIP-1967")
            info.add_row("Implementation", str(proxy["impl"]))
            if proxy["admin"]:
                eoa_tag = " (EOA ⚠️)" if report.get("proxy_admin_is_eoa") else ""
                info.add_row("ProxyAdmin", f"{proxy['admin']}{eoa_tag}")
            if proxy["beacon"]:
                info.add_row("Beacon", str(proxy["beacon"]))
        else:
            info.add_row("代理", "否")
        info.add_row("总选择器数", str(len(report["selectors"])))
        cc = report["danger_counts"]
        info.add_row("危险分布",
                     f"🔴 {cc.get('RED',0)}  🟠 {cc.get('ORANGE',0)}  "
                     f"🟡 {cc.get('YELLOW',0)}  🟢 {cc.get('GREEN',0)}  "
                     f"⚪ {cc.get('UNKNOWN',0)}")
        console.print(info)

    # 关键状态
    state = report.get("state", {})
    if state:
        console.print("\n[bold cyan]关键状态:[/bold cyan]" if HAS_RICH else "\n关键状态:")
        for k, v in state.items():
            tag = ""
            if k == "admin" and report.get("admin_is_eoa"):
                tag = " [red](EOA ⚠️)[/red]" if HAS_RICH else " (EOA)"
            elif k == "owner" and report.get("owner_is_eoa"):
                tag = " [red](EOA ⚠️)[/red]" if HAS_RICH else " (EOA)"
            console.print(f"  • {k:<14} = {v}{tag}")

    # 选择器碰撞警告
    proxy_col = report["collisions"]["proxy"]
    dict_col = report["collisions"]["dict"]
    if proxy_col:
        console.print("\n[bold red]🚨 CRITICAL: 代理↔实现选择器冲突[/bold red]"
                      if HAS_RICH else "\n🚨 代理↔实现选择器冲突")
        for c in proxy_col[:5]:
            console.print(f"  • {c['selector']}  {c['message']}")
    high_dict = [c for c in dict_col if c["level"] == "HIGH"]
    if high_dict:
        console.print(f"\n[yellow]⚠️ HIGH 字典碰撞 ({len(high_dict)} 个):[/yellow]"
                      if HAS_RICH else f"\n⚠️ 字典碰撞 ({len(high_dict)} 个)")
        for c in high_dict[:3]:
            console.print(f"  • {c['selector']}  {c['message']}")

    # 高危函数 Top
    red_funcs = [f for f in report["functions"] if f["danger"] == "RED"]
    orange_funcs = [f for f in report["functions"] if f["danger"] == "ORANGE"]
    if red_funcs or orange_funcs:
        if HAS_RICH:
            ft = Table(title="\n高危函数清单", box=box.SIMPLE, show_header=True)
            ft.add_column("等级", width=4)
            ft.add_column("选择器", width=12)
            ft.add_column("签名")
            for f in red_funcs[:8]:
                sig = " | ".join(f["real_signatures"][:1]) or "【未知】"
                ft.add_row("🔴", f["selector"], sig)
            for f in orange_funcs[:8]:
                sig = " | ".join(f["real_signatures"][:1]) or "【未知】"
                ft.add_row("🟠", f["selector"], sig)
            console.print(ft)

    # 风险原因
    if report["risk_reasons"]:
        console.print(f"\n[bold]📋 风险评分原因 ({score}/100):[/bold]"
                      if HAS_RICH else f"\n风险评分原因 ({score}/100):")
        for reason in report["risk_reasons"]:
            console.print(f"  • {reason}")


def print_summary_table(reports):
    """批量审计的汇总表"""
    if not HAS_RICH:
        print("\n=== 批量审计汇总 ===")
        print(f"  {'等级':<10} {'评分':>4}  {'地址':<44}  {'代理':<4}  RED  ORG  YEL  碰撞  admin/owner")
        print("-" * 100)
        for r in sorted(reports, key=lambda x: -x.get("risk_score", 0)):
            level = r.get("risk_level", "ERR")
            score = r.get("risk_score", 0)
            cc = r.get("danger_counts", {})
            proxy = "Y" if r.get("proxy", {}).get("is_proxy") else ""
            coll = len(r.get("collisions", {}).get("proxy", [])) + sum(
                1 for c in r.get("collisions", {}).get("dict", []) if c["level"] == "HIGH")
            state = r.get("state", {})
            ao = []
            if state.get("admin"): ao.append("a:" + ("EOA" if r.get("admin_is_eoa") else "C"))
            if state.get("owner"): ao.append("o:" + ("EOA" if r.get("owner_is_eoa") else "C"))
            print(f"  {level:<10} {score:>4}  {r['address']:<44}  {proxy:<4}  "
                  f"{cc.get('RED',0):>3}  {cc.get('ORANGE',0):>3}  "
                  f"{cc.get('YELLOW',0):>3}  {coll:>4}  {' '.join(ao) or '-'}")
        total = len(reports)
        crit = sum(1 for r in reports if r.get("risk_level") == "CRITICAL")
        high = sum(1 for r in reports if r.get("risk_level") == "HIGH")
        med  = sum(1 for r in reports if r.get("risk_level") == "MEDIUM")
        low  = sum(1 for r in reports if r.get("risk_level") == "LOW")
        err  = sum(1 for r in reports if r.get("error") and not r.get("bytecode_size"))
        print(f"\n统计：共 {total} 个 / CRITICAL:{crit}  HIGH:{high}  MEDIUM:{med}  LOW:{low}  失败:{err}")
        return

    LEVEL_COLOR = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange1", "CRITICAL": "red"}
    LEVEL_ICON  = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}

    table = Table(
        title=f"\n📊 批量审计汇总 ({len(reports)} 个合约)",
        box=box.ROUNDED, show_lines=True, expand=True,
    )
    table.add_column("等级",        min_width=10, no_wrap=True)
    table.add_column("评分",        min_width=5,  justify="right")
    table.add_column("合约地址",    min_width=42, no_wrap=True)
    table.add_column("代理",        min_width=4,  justify="center")
    table.add_column("RED",         min_width=4,  justify="right")
    table.add_column("ONG",         min_width=4,  justify="right")
    table.add_column("YEL",         min_width=4,  justify="right")
    table.add_column("碰撞",        min_width=4,  justify="right")
    table.add_column("admin/owner", min_width=14, no_wrap=True)

    sorted_reports = sorted(reports, key=lambda r: -r.get("risk_score", 0))

    for r in sorted_reports:
        if r.get("error") and not r.get("bytecode_size"):
            table.add_row("[grey50]ERROR[/grey50]", "—", r["address"],
                          "—", "—", "—", "—", "—", r.get("error","")[:16])
            continue

        level  = r.get("risk_level", "LOW")
        score  = r.get("risk_score", 0)
        color  = LEVEL_COLOR.get(level, "white")
        icon   = LEVEL_ICON.get(level, "")
        cc     = r.get("danger_counts", {})
        proxy_yes = "✅" if r.get("proxy", {}).get("is_proxy") else ""
        coll_count = len(r.get("collisions", {}).get("proxy", [])) + sum(
            1 for c in r.get("collisions", {}).get("dict", []) if c["level"] == "HIGH")
        coll_str = f"[red]{coll_count}[/red]" if coll_count > 0 else "0"

        state = r.get("state", {})
        ao = []
        if state.get("admin"):
            ao.append("a:" + ("EOA⚠" if r.get("admin_is_eoa") else "C"))
        if state.get("owner"):
            ao.append("o:" + ("EOA⚠" if r.get("owner_is_eoa") else "C"))
        ao_str = " ".join(ao) or "—"

        table.add_row(
            f"{icon} [{color}]{level}[/{color}]",
            str(score),
            r["address"],
            proxy_yes,
            f"[red]{cc.get('RED',0)}[/red]"    if cc.get("RED", 0) > 0    else "0",
            f"[yellow]{cc.get('ORANGE',0)}[/yellow]" if cc.get("ORANGE", 0) > 0 else "0",
            str(cc.get("YELLOW", 0)),
            coll_str,
            ao_str,
        )

    console.print(table)

    total = len(reports)
    crit  = sum(1 for r in reports if r.get("risk_level") == "CRITICAL")
    high  = sum(1 for r in reports if r.get("risk_level") == "HIGH")
    med   = sum(1 for r in reports if r.get("risk_level") == "MEDIUM")
    low   = sum(1 for r in reports if r.get("risk_level") == "LOW")
    err   = sum(1 for r in reports if r.get("error") and not r.get("bytecode_size"))

    console.print(
        f"\n📈 [bold]统计：[/bold] 共 {total} 个 / "
        f"🔴 CRITICAL: {crit} · 🟠 HIGH: {high} · "
        f"🟡 MEDIUM: {med} · 🟢 LOW: {low} · ❌ 失败: {err}"
    )


def write_csv(reports, path):
    """写 CSV 摘要"""
    fields = ["address", "chain_id", "risk_score", "risk_level",
              "bytecode_size", "is_proxy", "implementation", "proxy_admin",
              "proxy_admin_is_eoa", "admin", "admin_is_eoa", "owner",
              "owner_is_eoa", "RED", "ORANGE", "YELLOW", "GREEN", "UNKNOWN",
              "proxy_collisions", "dict_collisions_high", "selectors_total",
              "name", "symbol", "totalSupply", "risk_reasons", "error"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in reports:
            cc = r.get("danger_counts", {})
            state = r.get("state", {})
            row = {
                "address": r["address"],
                "chain_id": r.get("chain_id", ""),
                "risk_score": r.get("risk_score", 0),
                "risk_level": r.get("risk_level", ""),
                "bytecode_size": r.get("bytecode_size", 0),
                "is_proxy": r["proxy"]["is_proxy"] if "proxy" in r else False,
                "implementation": r["proxy"].get("impl", "") if "proxy" in r else "",
                "proxy_admin": r["proxy"].get("admin", "") if "proxy" in r else "",
                "proxy_admin_is_eoa": r.get("proxy_admin_is_eoa"),
                "admin": state.get("admin", ""),
                "admin_is_eoa": r.get("admin_is_eoa"),
                "owner": state.get("owner", ""),
                "owner_is_eoa": r.get("owner_is_eoa"),
                "RED": cc.get("RED", 0),
                "ORANGE": cc.get("ORANGE", 0),
                "YELLOW": cc.get("YELLOW", 0),
                "GREEN": cc.get("GREEN", 0),
                "UNKNOWN": cc.get("UNKNOWN", 0),
                "proxy_collisions": len(r.get("collisions", {}).get("proxy", [])),
                "dict_collisions_high": sum(1 for c in r.get("collisions", {}).get("dict", [])
                                            if c["level"] == "HIGH"),
                "selectors_total": len(r.get("selectors", [])),
                "name": state.get("name", ""),
                "symbol": state.get("symbol", ""),
                "totalSupply": state.get("totalSupply", ""),
                "risk_reasons": " | ".join(r.get("risk_reasons", [])),
                "error": r.get("error", ""),
            }
            w.writerow(row)


# ==============================================================================
# 输入收集
# ==============================================================================
def collect_addresses(args):
    """从命令行 / 文件 / stdin 收集地址列表"""
    addrs = []
    if args.addresses:
        for a in args.addresses:
            addrs.extend(re.findall(r"0x[a-fA-F0-9]{40}", a))
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                addrs.extend(re.findall(r"0x[a-fA-F0-9]{40}", line))
    if args.stdin:
        for line in sys.stdin:
            addrs.extend(re.findall(r"0x[a-fA-F0-9]{40}", line))

    # 去重保序
    seen = set()
    unique = []
    for a in addrs:
        a = Web3.to_checksum_address(a)
        if a not in seen:
            seen.add(a)
            unique.append(a)
    return unique


# ==============================================================================
# CLI
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="EVM 合约批量审计一条龙工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  audit.py 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559
  audit.py 0xA 0xB 0xC --rpc https://my-rpc.io
  audit.py --file addrs.txt --chain arb --workers 5 --json out.json --csv out.csv
  audit.py --file addrs.txt --min-risk 50      # 只显示评分 >=50 的
  audit.py 0xAddr --deep                       # 深度模式（含 admin/owner 探测）
  cat addrs.txt | audit.py --stdin --chain arb

环境变量：
  RPC_URL    默认 RPC（被 --rpc 和 --chain 覆盖）
""",
    )
    parser.add_argument("addresses", nargs="*",
                        help="一个或多个合约地址")
    parser.add_argument("--file", "-f",
                        help="批量地址文件，每行一个地址")
    parser.add_argument("--stdin", action="store_true",
                        help="从标准输入读取地址")

    # RPC 配置（核心：完全自定义）
    parser.add_argument("--rpc",
                        help="自定义 RPC URL（覆盖 --chain）")
    parser.add_argument("--chain",
                        help=f"预设链：{', '.join(CHAINS.keys())}")

    # 输出
    parser.add_argument("--json", "-j", metavar="PATH",
                        help="保存完整 JSON 报告")
    parser.add_argument("--csv", "-c", metavar="PATH",
                        help="保存 CSV 摘要")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="安静模式（仅打印汇总表）")
    parser.add_argument("--no-summary", action="store_true",
                        help="不打印汇总表")

    # 行为
    parser.add_argument("--deep", "-d", action="store_true",
                        help="深度模式：含字符串提取 + 关键状态读取（admin/owner/...）")
    parser.add_argument("--no-lookup", action="store_true",
                        help="跳过函数名反查（更快但信息少）")
    parser.add_argument("--workers", "-w", type=int, default=4,
                        help="并发线程数（默认 4）")
    parser.add_argument("--min-risk", type=int, default=0,
                        help="只显示风险评分 >= N 的合约")
    parser.add_argument("--timeout", type=int, default=30,
                        help="每个 RPC 请求超时秒数（默认 30）")

    args = parser.parse_args()

    # 解析 RPC（优先级：--rpc > --chain > RPC_URL > 默认 arb）
    if args.rpc:
        rpc_url = args.rpc
    elif args.chain:
        if args.chain.lower() not in CHAINS:
            console.print(f"[red]❌ 未知链: {args.chain}[/red]" if HAS_RICH
                          else f"❌ 未知链: {args.chain}")
            console.print(f"   可选: {', '.join(CHAINS.keys())}")
            sys.exit(1)
        rpc_url = CHAINS[args.chain.lower()]
    elif os.getenv("RPC_URL"):
        rpc_url = os.getenv("RPC_URL")
    else:
        rpc_url = CHAINS["arb"]
        console.print("[yellow]ℹ️ 未指定 --rpc/--chain，使用默认 Arbitrum RPC[/yellow]"
                      if HAS_RICH else "ℹ️ 默认使用 Arbitrum RPC")

    # 连接 RPC
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": args.timeout}))
    if not w3.is_connected():
        console.print(f"[red]❌ 无法连接 RPC: {rpc_url}[/red]" if HAS_RICH
                      else f"❌ 无法连接 RPC: {rpc_url}")
        sys.exit(1)

    chain_id = w3.eth.chain_id
    if not args.quiet:
        console.print(f"🌐 已连接 [cyan]{rpc_url}[/cyan]  Chain ID: [bold]{chain_id}[/bold]"
                      if HAS_RICH else f"🌐 已连接 {rpc_url} (Chain {chain_id})")

    # 收集地址
    addresses = collect_addresses(args)
    if not addresses:
        console.print("[red]❌ 未提供任何合约地址。用法：audit.py <地址> 或 --file <文件>[/red]"
                      if HAS_RICH else "❌ 未提供地址")
        parser.print_help()
        sys.exit(1)

    if not args.quiet:
        console.print(f"📋 待审计合约: [bold]{len(addresses)}[/bold] 个 "
                      f"(深度模式: {'✅' if args.deep else '❌'}, "
                      f"并发: {args.workers})\n"
                      if HAS_RICH else f"待审计: {len(addresses)} 个")

    # 并发审计
    reports = []
    completed = 0

    def task(addr):
        return audit_contract(w3, addr, deep=args.deep, lookup=not args.no_lookup)

    if args.workers > 1 and len(addresses) > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(task, a): a for a in addresses}
            for fut in as_completed(futures):
                addr = futures[fut]
                completed += 1
                try:
                    r = fut.result()
                    reports.append(r)
                    if not args.quiet:
                        score = r.get("risk_score", 0)
                        level = r.get("risk_level", "ERR")
                        icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠",
                                "CRITICAL": "🔴", "ERR": "❌"}.get(level, "?")
                        console.print(f"  [{completed}/{len(addresses)}] {icon} "
                                      f"{addr[:14]}…  评分 {score}  [{level}]")
                except Exception as e:
                    reports.append({"address": addr, "error": str(e),
                                    "bytecode_size": 0, "risk_score": 0,
                                    "risk_level": "ERR", "proxy": {"is_proxy": False},
                                    "danger_counts": {}, "collisions": {"proxy": [], "dict": []}})
    else:
        for addr in addresses:
            r = task(addr)
            reports.append(r)
            completed += 1
            if not args.quiet:
                score = r.get("risk_score", 0)
                level = r.get("risk_level", "ERR")
                console.print(f"  [{completed}/{len(addresses)}] "
                              f"{addr[:14]}…  评分 {score}  [{level}]")

    # 过滤 min-risk
    filtered = [r for r in reports if r.get("risk_score", 0) >= args.min_risk]

    # 详细打印
    if not args.quiet:
        for r in sorted(filtered, key=lambda x: -x.get("risk_score", 0)):
            print_report(r)

    # 汇总表
    if not args.no_summary:
        print_summary_table(reports)

    # 输出 JSON
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n📝 JSON 报告: [green]{args.json}[/green]"
                      if HAS_RICH else f"\nJSON 报告: {args.json}")

    if args.csv:
        write_csv(reports, args.csv)
        console.print(f"📊 CSV 摘要: [green]{args.csv}[/green]"
                      if HAS_RICH else f"CSV 摘要: {args.csv}")

    # 退出码：有 CRITICAL 时返回 2，HIGH 返回 1，否则 0
    has_crit = any(r.get("risk_level") == "CRITICAL" for r in reports)
    has_high = any(r.get("risk_level") == "HIGH" for r in reports)
    sys.exit(2 if has_crit else (1 if has_high else 0))


if __name__ == "__main__":
    main()
