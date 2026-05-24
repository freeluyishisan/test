#!/usr/bin/env python3
"""
contract_interact.py —— EVM 合约交互工具（攻防 + 运维全功能）
================================================================

功能集：
  • info       —— 显示合约函数清单（轻量侦察）
  • read       —— 调用 view 函数（免费）
  • call       —— 调用任意函数（自动判断 view/write）
  • write      —— 显式发送交易（花 gas）
  • simulate   —— 用 eth_call 模拟交易效果，不上链
  • encode     —— 编码 calldata（不发送）
  • decode     —— 解码 calldata
  • balance    —— 查询地址 ETH/原生币余额
  • nonce      —— 查询地址 nonce
  • raw        —— 原始 calldata 调用（高级用法）

⚠️⚠️⚠️ 安全提示 ⚠️⚠️⚠️
  • 本工具支持发送写交易，会真实消耗 gas、改链上状态
  • 私钥/keystore 涉及资金，请只在自己掌控的环境运行
  • 推荐先用 --simulate 模拟一遍再发真实交易
  • 默认开启交互确认，--yes 跳过（自动化时使用）

依赖：pip install web3 eth-account rich

用法举例：
  # 查看合约信息
  python contract_interact.py info 0x68d319Aa647e67e00D3d97bbd2bDF3bb05575559

  # 调用 view（不花钱）
  python contract_interact.py read 0xToken "balanceOf(address)" 0x123...
  python contract_interact.py read 0xToken "name()"

  # 模拟一笔写交易（不上链，只看会不会 revert）
  python contract_interact.py write 0xToken "transfer(address,uint256)" \\
      0x123... 1000000000000000000 --key $PK --simulate

  # 真实发送（先模拟后发送，自动确认）
  python contract_interact.py write 0xToken "transfer(address,uint256)" \\
      0x123... "1 ether" --key $PK --yes

  # 用 keystore（推荐生产场景）
  python contract_interact.py write 0xToken "claimRewards()" \\
      --keystore ~/keys/op.json

  # 编码 calldata（离线生成）
  python contract_interact.py encode "transfer(address,uint256)" 0x123... 1000

  # 解码 calldata
  python contract_interact.py decode 0xa9059cbb000000000000000000000000...

  # 本地节点（Anvil/Hardhat/Geth）
  python contract_interact.py read 0xToken "balanceOf(address)" 0xMe \\
      --rpc http://127.0.0.1:8545

  # 多链一键切换
  python contract_interact.py read 0xToken "balanceOf(address)" 0xMe --chain bsc
  python contract_interact.py read 0xToken "totalSupply()" --chain base
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from getpass import getpass
from typing import Any, Optional

from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw): print(*a)
    console = _C()


# ============================================================================
# 多链 RPC + Scanner 字典
# ============================================================================
CHAINS = {
    # 链 ID  RPC URL                                              Scanner / 浏览器              原生币
    "eth":      ("https://eth.llamarpc.com",                  "https://api.etherscan.io/api",      "ETH",  1),
    "arb":      ("https://arb1.arbitrum.io/rpc",              "https://api.arbiscan.io/api",       "ETH",  42161),
    "arbitrum": ("https://arb1.arbitrum.io/rpc",              "https://api.arbiscan.io/api",       "ETH",  42161),
    "op":       ("https://mainnet.optimism.io",               "https://api-optimistic.etherscan.io/api", "ETH", 10),
    "base":     ("https://mainnet.base.org",                  "https://api.basescan.org/api",      "ETH",  8453),
    "bsc":      ("https://bsc-dataseed.binance.org",          "https://api.bscscan.com/api",       "BNB",  56),
    "polygon":  ("https://polygon-rpc.com",                   "https://api.polygonscan.com/api",   "POL",  137),
    "avax":     ("https://api.avax.network/ext/bc/C/rpc",     "https://api.snowtrace.io/api",      "AVAX", 43114),
    "scroll":   ("https://rpc.scroll.io",                     "https://api.scrollscan.com/api",    "ETH",  534352),
    "linea":    ("https://rpc.linea.build",                   "https://api.lineascan.build/api",   "ETH",  59144),
    "blast":    ("https://rpc.blast.io",                      "https://api.blastscan.io/api",      "ETH",  81457),
    "mantle":   ("https://rpc.mantle.xyz",                    "https://api.mantlescan.xyz/api",    "MNT",  5000),
    "celo":     ("https://forno.celo.org",                    "https://api.celoscan.io/api",       "CELO", 42220),
    # 本地节点（默认 Anvil/Hardhat/Geth 端口）
    "local":    ("http://127.0.0.1:8545",                     "",                                  "ETH",  31337),
    "anvil":    ("http://127.0.0.1:8545",                     "",                                  "ETH",  31337),
    "hardhat":  ("http://127.0.0.1:8545",                     "",                                  "ETH",  31337),
    # 测试网
    "sepolia":  ("https://sepolia.gateway.tenderly.co",       "https://api-sepolia.etherscan.io/api", "ETH", 11155111),
    "holesky":  ("https://ethereum-holesky.publicnode.com",   "https://api-holesky.etherscan.io/api", "ETH", 17000),
}


def resolve_rpc(chain: Optional[str], rpc: Optional[str]) -> tuple:
    """
    返回 (rpc_url, scanner_url, native_symbol, chain_id_hint)
    优先级：--rpc 显式指定 > --chain 预设 > 环境变量 RPC_URL > 默认 arb
    """
    # 1. 显式 --rpc
    if rpc:
        return (rpc, "", "ETH", None)
    # 2. --chain 预设
    if chain:
        if chain.lower() not in CHAINS:
            raise ValueError(f"未知链：{chain}。可选: {', '.join(CHAINS.keys())}")
        return CHAINS[chain.lower()]
    # 3. 环境变量
    env_rpc = os.getenv("RPC_URL")
    if env_rpc:
        return (env_rpc, "", "ETH", None)
    # 4. 默认 Arbitrum
    return CHAINS["arb"]


# ============================================================================
# 工具函数：选择器、ABI 编码解码
# ============================================================================
def function_selector(signature: str) -> bytes:
    """
    计算函数选择器：keccak256(signature)[:4]
    Foundry 风格 'name()(string)' 会被剥离 returns 部分，只对 'name()' 计算。
    """
    canonical = strip_returns(canonicalize_signature(signature))
    return keccak(text=canonical)[:4]


def strip_returns(sig: str) -> str:
    """
    剥离 Foundry 风格的 returns：
      'name()(string)'             → 'name()'
      'balanceOf(address)(uint256)' → 'balanceOf(address)'
      'swap(uint256) returns (uint)' → 'swap(uint256)'
    """
    # 形式 1: ... returns (...)
    if "returns" in sig:
        return sig[:sig.index("returns")].rstrip().rstrip(",")
    # 形式 2: foo()(T) — 找第一对配平的括号，后面如果还有 ( 就剥掉
    if "(" not in sig:
        return sig
    start = sig.index("(")
    depth = 1
    end = start + 1
    while end < len(sig) and depth > 0:
        if sig[end] == "(":
            depth += 1
        elif sig[end] == ")":
            depth -= 1
        if depth == 0:
            break
        end += 1
    head = sig[:end+1]
    rest = sig[end+1:].strip()
    if rest.startswith("("):
        return head
    return sig


def canonicalize_signature(sig: str) -> str:
    """规范化签名：去空格、补 uint256 等"""
    sig = sig.strip()
    # 把 uint -> uint256, int -> int256
    sig = re.sub(r"\buint\b", "uint256", sig)
    sig = re.sub(r"\bint\b", "int256", sig)
    sig = re.sub(r"\s+", "", sig)
    return sig


def parse_arg_types(sig: str) -> list:
    """
    从 transfer(address,uint256) 提取 ['address', 'uint256']
    也支持 Foundry 风格 'name()(string)' —— 只取第一对括号内（输入类型）。
    """
    sig = canonicalize_signature(sig)
    # 找到第一对括号（即输入参数）
    start = sig.index("(")
    depth = 1
    end = start + 1
    while end < len(sig) and depth > 0:
        if sig[end] == "(":
            depth += 1
        elif sig[end] == ")":
            depth -= 1
        if depth == 0:
            break
        end += 1
    inside = sig[start+1:end]
    if not inside:
        return []
    # 处理嵌套 tuple、数组
    types = []
    depth = 0
    cur = ""
    for c in inside:
        if c == "(":
            depth += 1
            cur += c
        elif c == ")":
            depth -= 1
            cur += c
        elif c == "," and depth == 0:
            types.append(cur)
            cur = ""
        else:
            cur += c
    if cur:
        types.append(cur)
    return types


def parse_return_types(sig: str) -> list:
    """
    解析 Foundry 风格的 returns 类型：
      "name()(string)"            → ["string"]
      "balanceOf(address)(uint256)" → ["uint256"]
      "swap(...) returns (uint)"  → ["uint256"]
    没有显式 returns 时返回空列表。
    """
    sig = canonicalize_signature(sig)
    # 模式 1: "func() returns (T)"
    if "returns" in sig:
        ret_part = sig[sig.index("returns")+7:].strip()
        return parse_arg_types(ret_part)
    # 模式 2: "func()(T)" Foundry 风格
    # 找第一对括号结束后还有第二对
    start = sig.index("(")
    depth = 1
    end = start + 1
    while end < len(sig) and depth > 0:
        if sig[end] == "(":
            depth += 1
        elif sig[end] == ")":
            depth -= 1
        if depth == 0:
            break
        end += 1
    rest = sig[end+1:].strip()
    if rest.startswith("("):
        return parse_arg_types(rest)
    return []


def parse_value(arg_type: str, raw: str, w3: Web3) -> Any:
    """
    把命令行的字符串值解析成对应类型。
    支持：
      address  → 自动 checksum
      uintN    → 数字 / 0x前缀十六进制 / "1 ether" / "100 gwei"
      bool     → true/false/1/0/yes/no
      bytesN   → 0x...
      string   → 直接
      T[]      → JSON 数组
    """
    arg_type = arg_type.strip()
    if arg_type == "address":
        return to_checksum_address(raw)

    if arg_type.startswith("uint") or arg_type.startswith("int"):
        s = raw.strip()
        # 货币单位简写
        m = re.match(r"^([0-9.]+)\s*(ether|eth|wei|gwei|finney|szabo)$", s, re.I)
        if m:
            num, unit = m.groups()
            unit = unit.lower()
            if unit == "eth":
                unit = "ether"
            return w3.to_wei(num, unit)
        if s.lower().startswith("0x"):
            return int(s, 16)
        # 支持科学计数法 1e18
        if "e" in s.lower() and "." not in s:
            return int(float(s))
        return int(s)

    if arg_type == "bool":
        return raw.lower() in ("true", "1", "yes", "y", "t")

    if arg_type == "bytes" or arg_type.startswith("bytes"):
        if raw.startswith("0x"):
            return bytes.fromhex(raw[2:])
        return raw.encode()

    if arg_type == "string":
        return raw

    # 数组
    if "[" in arg_type:
        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            items = [x.strip() for x in raw.split(",")]
        # 取掉最后一对 []
        sub_type = arg_type.rsplit("[", 1)[0]
        return [parse_value(sub_type, str(x), w3) for x in items]

    # 兜底
    return raw


def encode_calldata(signature: str, args: list, w3: Web3) -> bytes:
    """编码完整 calldata：selector + abi-encoded args"""
    from eth_abi import encode

    selector = function_selector(signature)
    arg_types = parse_arg_types(signature)
    if len(arg_types) != len(args):
        raise ValueError(
            f"参数个数不匹配：签名要 {len(arg_types)} 个 ({arg_types})，"
            f"但只给了 {len(args)} 个"
        )
    parsed_args = [parse_value(t, v, w3) for t, v in zip(arg_types, args)]
    encoded = encode(arg_types, parsed_args)
    return selector + encoded


def decode_return_value(signature: str, raw_bytes: bytes) -> Any:
    """
    根据签名末尾的 returns(...) 或 Foundry 风格 ()(T) 解码返回值。
    没有显式 return 类型时返回原始 bytes。
    """
    from eth_abi import decode

    if not raw_bytes:
        return None
    ret_types = parse_return_types(signature)
    if not ret_types:
        return raw_bytes
    try:
        return decode(ret_types, raw_bytes)
    except Exception:
        return raw_bytes


# ============================================================================
# 私钥/账户管理
# ============================================================================
def load_account(args) -> Optional[Account]:
    """
    多种来源加载账户，优先级：
      1. --key 命令行
      2. --keystore JSON 文件
      3. 环境变量 PRIVATE_KEY
      4. 环境变量 KEYSTORE_PATH (+ KEYSTORE_PASSWORD)
    """
    key = getattr(args, "key", None)
    keystore = getattr(args, "keystore", None)

    if not key:
        key = os.getenv("PRIVATE_KEY")
    if not keystore:
        keystore = os.getenv("KEYSTORE_PATH")

    if key:
        if not key.startswith("0x"):
            key = "0x" + key
        return Account.from_key(key)

    if keystore:
        with open(os.path.expanduser(keystore)) as f:
            ks_data = json.load(f)
        password = os.getenv("KEYSTORE_PASSWORD")
        if not password:
            password = getpass(f"🔐 请输入 keystore 密码 ({keystore}): ")
        try:
            pk = Account.decrypt(ks_data, password)
        except Exception as e:
            raise ValueError(f"keystore 解密失败：{e}")
        return Account.from_key(pk)

    return None


# ============================================================================
# 静态调用 / 模拟交易
# ============================================================================
def static_call(w3: Web3, to: str, calldata: bytes, sender: Optional[str] = None,
                value: int = 0) -> bytes:
    """eth_call - 不消耗 gas，只读"""
    tx = {"to": to_checksum_address(to), "data": calldata, "value": value}
    if sender:
        tx["from"] = to_checksum_address(sender)
    return w3.eth.call(tx)


# ============================================================================
# 写交易构造与发送
# ============================================================================
@dataclass
class TxResult:
    tx_hash: str
    block_number: int
    gas_used: int
    status: int
    logs: list


def build_tx(w3: Web3, account: Account, to: str, calldata: bytes,
             value: int = 0, gas_limit: Optional[int] = None,
             gas_price_gwei: Optional[float] = None,
             priority_gwei: Optional[float] = None) -> dict:
    """构造交易，自动 EIP-1559（或在不支持的链上 fallback 到 legacy）"""
    to_addr = to_checksum_address(to)
    nonce = w3.eth.get_transaction_count(account.address, "pending")
    chain_id = w3.eth.chain_id

    # 估算 gas（除非用户显式指定）
    if not gas_limit:
        try:
            gas_limit = w3.eth.estimate_gas({
                "from": account.address,
                "to": to_addr,
                "data": calldata,
                "value": value,
            })
            # 加 20% buffer
            gas_limit = int(gas_limit * 1.2)
        except Exception as e:
            console.print(f"[yellow]⚠️ 估算 gas 失败：{e}[/yellow]" if HAS_RICH
                          else f"⚠️ 估算 gas 失败：{e}")
            console.print("[yellow]   使用默认 gas_limit=300000，建议显式 --gas-limit[/yellow]"
                          if HAS_RICH else "   使用默认 gas_limit=300000")
            gas_limit = 300000

    base_tx = {
        "from": account.address,
        "to": to_addr,
        "data": calldata,
        "value": int(value),
        "gas": gas_limit,
        "nonce": nonce,
        "chainId": chain_id,
    }

    # 若用户指定了 gas-price，走 legacy
    if gas_price_gwei is not None:
        base_tx["gasPrice"] = w3.to_wei(gas_price_gwei, "gwei")
        base_tx["type"] = 0
        return base_tx

    # 否则尝试 EIP-1559
    try:
        latest = w3.eth.get_block("latest")
        base_fee = latest.get("baseFeePerGas")
        if base_fee is not None:
            priority = w3.to_wei(priority_gwei or 1.5, "gwei")
            max_fee = base_fee * 2 + priority
            base_tx["maxFeePerGas"] = max_fee
            base_tx["maxPriorityFeePerGas"] = priority
            base_tx["type"] = 2
            return base_tx
    except Exception:
        pass

    # Fallback: legacy
    try:
        gas_price = w3.eth.gas_price
    except Exception:
        gas_price = w3.to_wei(1, "gwei")
    base_tx["gasPrice"] = gas_price
    base_tx["type"] = 0
    return base_tx


def print_tx_summary(w3: Web3, tx: dict, native_symbol: str = "ETH",
                     signature: str = "", args: list = None):
    """漂亮打印交易摘要"""
    if HAS_RICH:
        table = Table(title="📝 即将发送的交易", box=box.ROUNDED, show_header=False)
        table.add_column("字段", style="cyan")
        table.add_column("值")

        table.add_row("From",    str(tx["from"]))
        table.add_row("To",      str(tx["to"]))
        table.add_row("Value",   f"{w3.from_wei(tx['value'], 'ether')} {native_symbol}  ({tx['value']} wei)")
        if signature:
            table.add_row("函数",  signature)
        if args:
            table.add_row("参数",  json.dumps([str(a) for a in args], ensure_ascii=False))
        table.add_row("Nonce",   str(tx["nonce"]))
        table.add_row("Gas Limit", f"{tx['gas']:,}")

        if "maxFeePerGas" in tx:
            table.add_row("交易类型", "EIP-1559 (type 2)")
            table.add_row("Max Fee",     f"{w3.from_wei(tx['maxFeePerGas'], 'gwei'):.4f} gwei")
            table.add_row("Priority Fee", f"{w3.from_wei(tx['maxPriorityFeePerGas'], 'gwei'):.4f} gwei")
            est_cost = tx["maxFeePerGas"] * tx["gas"]
        else:
            table.add_row("交易类型", "Legacy (type 0)")
            table.add_row("Gas Price", f"{w3.from_wei(tx['gasPrice'], 'gwei'):.4f} gwei")
            est_cost = tx["gasPrice"] * tx["gas"]

        table.add_row("Chain ID", str(tx["chainId"]))
        table.add_row("最大手续费", f"{w3.from_wei(est_cost, 'ether'):.6f} {native_symbol}")
        table.add_row("Calldata", "0x" + tx["data"].hex() if isinstance(tx["data"], bytes) else tx["data"])

        console.print(table)
    else:
        print("\n=== 即将发送的交易 ===")
        for k, v in tx.items():
            print(f"  {k}: {v}")


def confirm(prompt: str = "确认发送此交易吗？") -> bool:
    """交互式确认"""
    try:
        resp = input(f"\n{prompt} [yes/no]: ").strip().lower()
        return resp in ("y", "yes", "确认", "ok")
    except (EOFError, KeyboardInterrupt):
        return False


def send_tx(w3: Web3, account: Account, tx: dict, wait: bool = True) -> TxResult:
    """签名 + 发送 + 等待回执"""
    signed = account.sign_transaction(tx)
    raw = signed.rawTransaction if hasattr(signed, "rawTransaction") else signed.raw_transaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    hash_hex = tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash

    console.print(f"\n📤 已广播: [cyan]{hash_hex}[/cyan]" if HAS_RICH
                  else f"\n已广播: {hash_hex}")

    if not wait:
        return TxResult(hash_hex, 0, 0, -1, [])

    console.print("⏳ 等待上链...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

    status = receipt.status
    if status == 1:
        console.print(f"[green]✅ 已上链[/green] block #{receipt.blockNumber}, "
                      f"gas used: {receipt.gasUsed:,}" if HAS_RICH
                      else f"✅ 已上链 block #{receipt.blockNumber}, gas used: {receipt.gasUsed}")
    else:
        console.print(f"[red]❌ 交易失败 (revert)[/red]" if HAS_RICH else "❌ 交易失败")

    return TxResult(
        tx_hash=hash_hex,
        block_number=receipt.blockNumber,
        gas_used=receipt.gasUsed,
        status=status,
        logs=list(receipt.logs),
    )


# ============================================================================
# 子命令处理函数
# ============================================================================
def cmd_info(args, w3: Web3):
    """显示合约简要信息（轻量侦察）"""
    addr = to_checksum_address(args.address)
    code = w3.eth.get_code(addr)
    if not code:
        console.print("[red]❌ 这不是合约地址（EOA / 未部署）[/red]" if HAS_RICH
                      else "❌ 这不是合约地址")
        return

    # 简化版选择器提取
    selectors = set()
    bc = bytes(code)
    i = 0
    while i < len(bc):
        op = bc[i]
        if op == 0x63 and i + 4 < len(bc):
            sel = bc[i+1:i+5]
            if sel not in (b'\x00'*4, b'\xff'*4):
                selectors.add("0x" + sel.hex())
            i += 5
        elif 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1

    console.print(f"\n📦 合约: [cyan]{addr}[/cyan]")
    console.print(f"   字节码大小: [bold]{len(code)}[/bold] 字节")
    console.print(f"   Chain ID:  {w3.eth.chain_id}")
    console.print(f"   提取到选择器: [bold]{len(selectors)}[/bold] 个\n")

    for sel in sorted(selectors):
        console.print(f"  • {sel}")
    console.print(f"\n💡 想看完整侦察分析（含函数名反查、危险等级）请用 [cyan]contract_recon.py[/cyan]"
                  if HAS_RICH else
                  "\n💡 想看完整分析请用 contract_recon.py")


def cmd_read(args, w3: Web3):
    """调用 view 函数"""
    addr = to_checksum_address(args.address)
    sig = args.signature
    user_args = args.args or []

    # 编码 calldata
    try:
        calldata = encode_calldata(sig, user_args, w3)
    except Exception as e:
        console.print(f"[red]❌ 编码失败: {e}[/red]" if HAS_RICH else f"❌ 编码失败: {e}")
        sys.exit(1)

    sender = None
    if hasattr(args, "from_addr") and args.from_addr:
        sender = args.from_addr
    elif os.getenv("PRIVATE_KEY"):
        sender = Account.from_key(os.getenv("PRIVATE_KEY")).address

    console.print(f"\n📞 调用: [cyan]{sig}[/cyan]")
    console.print(f"   Calldata: 0x{calldata.hex()}")

    try:
        result = static_call(w3, addr, calldata, sender=sender)
    except Exception as e:
        console.print(f"[red]❌ 调用失败: {e}[/red]" if HAS_RICH else f"❌ 调用失败: {e}")
        sys.exit(1)

    console.print(f"\n[green]✅ 返回原始 bytes:[/green] 0x{result.hex()}" if HAS_RICH
                  else f"\n返回: 0x{result.hex()}")

    # 自动猜返回类型
    ret_types = parse_return_types(sig) if 'parse_return_types' in dir() else []
    if "returns" in sig or sig.count("(") >= 2:
        decoded = decode_return_value(sig, result)
        console.print(f"   解码后: [bold]{decoded}[/bold]" if HAS_RICH else f"解码: {decoded}")
    else:
        # 几个常见的返回类型尝试
        if len(result) == 32:
            try:
                as_int = int.from_bytes(result, "big")
                console.print(f"   作为 uint256: [bold]{as_int:,}[/bold]")
                # 如果像 18 decimals 的代币
                if as_int > 10**12:
                    console.print(f"   除 1e18:    [bold]{as_int / 10**18:.6f}[/bold]")
                # 如果像地址
                if as_int < 2**160 and as_int > 0:
                    addr_view = to_checksum_address("0x" + result.hex()[-40:])
                    console.print(f"   作为 address: [bold]{addr_view}[/bold]")
            except Exception:
                pass


def cmd_write(args, w3: Web3, native_symbol: str = "ETH"):
    """发送写交易（写函数）"""
    addr = to_checksum_address(args.address)
    sig = args.signature
    user_args = args.args or []

    account = load_account(args)
    if not account:
        console.print("[red]❌ 写交易需要私钥。请用 --key / --keystore / 环境变量 PRIVATE_KEY[/red]"
                      if HAS_RICH else
                      "❌ 写交易需要私钥")
        sys.exit(1)

    # 编码
    calldata = encode_calldata(sig, user_args, w3)

    # 解析 value
    value = 0
    if args.value:
        value = parse_value("uint256", args.value, w3)

    # 构造交易
    tx = build_tx(
        w3, account, addr, calldata,
        value=value,
        gas_limit=int(args.gas_limit) if args.gas_limit else None,
        gas_price_gwei=float(args.gas_price) if args.gas_price else None,
        priority_gwei=float(args.priority) if args.priority else None,
    )

    # 显示摘要
    parsed_args_for_display = [parse_value(t, v, w3) for t, v in
                               zip(parse_arg_types(sig), user_args)]
    print_tx_summary(w3, tx, native_symbol=native_symbol, signature=sig,
                     args=parsed_args_for_display)

    # 余额检查
    balance = w3.eth.get_balance(account.address)
    est_max = (tx.get("maxFeePerGas") or tx.get("gasPrice")) * tx["gas"] + tx["value"]
    if balance < est_max:
        console.print(f"\n[red]❌ 余额不足！需要 {w3.from_wei(est_max, 'ether'):.6f} {native_symbol}，"
                      f"但你只有 {w3.from_wei(balance, 'ether'):.6f}[/red]"
                      if HAS_RICH else
                      f"\n❌ 余额不足，需要 {w3.from_wei(est_max, 'ether')} {native_symbol}")
        if not args.simulate:
            sys.exit(1)

    # 模拟（无论 simulate 还是真发，都先模拟一下，避免白扔 gas）
    console.print("\n🔬 先用 eth_call 模拟交易...")
    try:
        sim_result = static_call(w3, addr, calldata, sender=account.address, value=value)
        console.print(f"[green]✅ 模拟成功[/green]，返回: 0x{sim_result.hex()}" if HAS_RICH
                      else f"✅ 模拟成功，返回: 0x{sim_result.hex()}")
    except Exception as e:
        msg = str(e)[:200]
        console.print(f"[red]❌ 模拟失败！发送也会 revert：[/red]\n   {msg}" if HAS_RICH
                      else f"❌ 模拟失败：{msg}")
        if not args.force:
            console.print("\n💡 加 --force 可以无视模拟失败强制发送")
            sys.exit(1)

    # 仅模拟
    if args.simulate:
        console.print("\n[yellow]🛑 --simulate 模式，未真实发送[/yellow]" if HAS_RICH
                      else "\n🛑 --simulate 模式，未真实发送")
        return

    # 交互确认
    if not args.yes:
        if not confirm():
            console.print("[yellow]🚫 已取消[/yellow]" if HAS_RICH else "🚫 已取消")
            return

    # 真实发送
    result = send_tx(w3, account, tx)

    # 链接
    if hasattr(args, "_explorer") and args._explorer:
        console.print(f"\n🔗 浏览器: {args._explorer}/tx/{result.tx_hash}")


def cmd_simulate(args, w3: Web3, native_symbol: str = "ETH"):
    """简化的模拟命令——等价于 write --simulate"""
    args.simulate = True
    args.force = False
    args.yes = True
    cmd_write(args, w3, native_symbol)


def cmd_call(args, w3: Web3, native_symbol: str = "ETH"):
    """智能 call —— 先 staticcall 试探是不是 view，是就 read，不是就提示用 write"""
    addr = to_checksum_address(args.address)
    sig = args.signature
    user_args = args.args or []
    calldata = encode_calldata(sig, user_args, w3)

    sender = None
    account = load_account(args)
    if account:
        sender = account.address

    try:
        result = static_call(w3, addr, calldata, sender=sender)
        console.print(f"[green]✅ staticcall 成功[/green]，结果: 0x{result.hex()}" if HAS_RICH
                      else f"✅ 成功: 0x{result.hex()}")
        if "returns" in sig:
            console.print(f"   解码: {decode_return_value(sig, result)}")
        if account:
            console.print("\n💡 这是 view 调用。如果想真发交易请用 [cyan]write[/cyan] 子命令"
                          if HAS_RICH else "\n💡 这是 view 调用，写交易请用 write")
    except Exception as e:
        console.print(f"[yellow]⚠️ staticcall 失败：{str(e)[:200]}[/yellow]" if HAS_RICH
                      else f"⚠️ staticcall 失败：{str(e)[:200]}")
        console.print("   这可能是写函数（需要发交易）。请改用 [cyan]write[/cyan] 子命令"
                      if HAS_RICH else "   请改用 write 子命令")


def cmd_encode(args, w3: Web3):
    """只编码 calldata，不发送"""
    sig = args.signature
    user_args = args.args or []
    calldata = encode_calldata(sig, user_args, w3)

    console.print(f"\n📦 签名: [cyan]{canonicalize_signature(sig)}[/cyan]")
    console.print(f"   选择器: [bold]0x{function_selector(sig).hex()}[/bold]")
    console.print(f"   完整 Calldata:")
    console.print(f"   [green]0x{calldata.hex()}[/green]" if HAS_RICH else f"   0x{calldata.hex()}")
    console.print(f"   长度: {len(calldata)} 字节")


def cmd_decode(args, w3: Web3):
    """解码 calldata"""
    raw = args.calldata.removeprefix("0x")
    if len(raw) < 8:
        console.print("[red]❌ calldata 长度不足 4 字节[/red]" if HAS_RICH
                      else "❌ calldata 长度不足")
        sys.exit(1)

    selector = "0x" + raw[:8]
    payload = bytes.fromhex(raw[8:])

    console.print(f"\n🔍 选择器: [cyan]{selector}[/cyan]")
    console.print(f"   参数数据 ({len(payload)} 字节): 0x{payload.hex()[:128]}{'...' if len(payload) > 64 else ''}")

    # 反查函数名
    try:
        import requests
        r = requests.get(
            f"https://api.openchain.xyz/signature-database/v1/lookup?function={selector}",
            timeout=5,
        )
        data = r.json().get("result", {}).get("function", {}).get(selector, [])
        if data:
            console.print(f"\n💡 可能的函数签名:")
            for item in data[:5]:
                name = item.get("name", "")
                console.print(f"   • {name}")
                # 尝试解码
                if args.try_decode and name:
                    try:
                        from eth_abi import decode
                        types = parse_arg_types(name)
                        decoded = decode(types, payload)
                        console.print(f"     解码: {decoded}")
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"[yellow]反查失败：{e}[/yellow]")

    # 用户提供了签名时手动解码
    if args.signature:
        from eth_abi import decode
        types = parse_arg_types(args.signature)
        try:
            decoded = decode(types, payload)
            console.print(f"\n✅ 按 [cyan]{args.signature}[/cyan] 解码: [bold]{decoded}[/bold]"
                          if HAS_RICH else f"\n按 {args.signature} 解码: {decoded}")
        except Exception as e:
            console.print(f"[red]❌ 用提供的签名解码失败：{e}[/red]")


def cmd_balance(args, w3: Web3, native_symbol: str = "ETH"):
    """查询地址余额"""
    addr = to_checksum_address(args.address)
    bal_wei = w3.eth.get_balance(addr)
    console.print(f"\n💰 [cyan]{addr}[/cyan]")
    console.print(f"   {w3.from_wei(bal_wei, 'ether'):.6f} {native_symbol}")
    console.print(f"   ({bal_wei:,} wei)")


def cmd_nonce(args, w3: Web3):
    """查询 nonce"""
    addr = to_checksum_address(args.address)
    n_pending = w3.eth.get_transaction_count(addr, "pending")
    n_latest = w3.eth.get_transaction_count(addr, "latest")
    console.print(f"\n🔢 [cyan]{addr}[/cyan]")
    console.print(f"   nonce (latest):  {n_latest}")
    console.print(f"   nonce (pending): {n_pending}")


def cmd_raw(args, w3: Web3, native_symbol: str = "ETH"):
    """原始 calldata 调用（高级用法）"""
    addr = to_checksum_address(args.address)
    calldata = bytes.fromhex(args.calldata.removeprefix("0x"))

    if args.write:
        account = load_account(args)
        if not account:
            console.print("[red]❌ raw write 需要私钥[/red]" if HAS_RICH else "❌ 需要私钥")
            sys.exit(1)

        value = parse_value("uint256", args.value, w3) if args.value else 0
        tx = build_tx(w3, account, addr, calldata, value=value,
                      gas_limit=int(args.gas_limit) if args.gas_limit else None)
        print_tx_summary(w3, tx, native_symbol=native_symbol)
        if not args.yes and not confirm():
            return
        send_tx(w3, account, tx)
    else:
        result = static_call(w3, addr, calldata)
        console.print(f"\n✅ 返回: 0x{result.hex()}")


# ============================================================================
# CLI 入口
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="EVM 合约交互工具（侦察+读+写+模拟+编码全功能）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  写交易功能会真实消耗 gas，请先用 --simulate 验证。

环境变量支持：
  PRIVATE_KEY        默认私钥（0x 开头）
  KEYSTORE_PATH      默认 keystore 路径
  KEYSTORE_PASSWORD  默认 keystore 密码（不设置会交互式询问）
  RPC_URL            默认 RPC URL
""",
    )
    parser.add_argument("--rpc", help="RPC URL（覆盖 --chain 和环境变量）")
    parser.add_argument("--chain", help=f"预设链：{', '.join(CHAINS.keys())}")

    # 共享的连接选项 —— 让 --chain/--rpc 在子命令前后都能用
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--rpc", help="RPC URL（同根选项）")
    common.add_argument("--chain", help="预设链（同根选项）")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # info
    p_info = sub.add_parser("info", help="查看合约函数列表", parents=[common])
    p_info.add_argument("address")

    # read
    p_read = sub.add_parser("read", help="调用 view 函数（不花 gas）", parents=[common])
    p_read.add_argument("address")
    p_read.add_argument("signature", help='函数签名，如 "balanceOf(address)"')
    p_read.add_argument("args", nargs="*", help="参数列表")
    p_read.add_argument("--from", dest="from_addr", help="模拟调用者地址")

    # call（智能）
    p_call = sub.add_parser("call", help="智能调用（自动判断 view/write）", parents=[common])
    p_call.add_argument("address")
    p_call.add_argument("signature")
    p_call.add_argument("args", nargs="*")
    p_call.add_argument("--key", help="私钥（用于 from 字段）")
    p_call.add_argument("--keystore", help="keystore 文件")

    # write
    p_write = sub.add_parser("write", help="发送交易（花 gas，会改链上状态）", parents=[common])
    p_write.add_argument("address")
    p_write.add_argument("signature")
    p_write.add_argument("args", nargs="*")
    p_write.add_argument("--key", help="私钥")
    p_write.add_argument("--keystore", help="keystore 文件路径")
    p_write.add_argument("--value", default="0", help="附带 ETH 数量，如 '1 ether'")
    p_write.add_argument("--gas-limit", help="自定义 gas limit")
    p_write.add_argument("--gas-price", help="自定义 gas price (gwei)，使用 legacy 模式")
    p_write.add_argument("--priority", help="EIP-1559 priority fee (gwei)，默认 1.5")
    p_write.add_argument("--simulate", action="store_true", help="只模拟不发送")
    p_write.add_argument("--force", action="store_true", help="模拟失败也强制发送")
    p_write.add_argument("--yes", "-y", action="store_true", help="跳过交互确认")

    # simulate（write --simulate 的快捷别名）
    p_sim = sub.add_parser("simulate", help="模拟交易（不上链）", parents=[common])
    p_sim.add_argument("address")
    p_sim.add_argument("signature")
    p_sim.add_argument("args", nargs="*")
    p_sim.add_argument("--key", help="私钥（用于 from 字段；只读不需要发送）")
    p_sim.add_argument("--keystore", help="keystore 文件")
    p_sim.add_argument("--value", default="0")
    p_sim.add_argument("--gas-limit")
    p_sim.add_argument("--gas-price")
    p_sim.add_argument("--priority")

    # encode
    p_enc = sub.add_parser("encode", help="编码 calldata（离线，不发送）")
    p_enc.add_argument("signature")
    p_enc.add_argument("args", nargs="*")

    # decode
    p_dec = sub.add_parser("decode", help="解码 calldata")
    p_dec.add_argument("calldata")
    p_dec.add_argument("--signature", help="如果你知道签名，加上可以解码参数")
    p_dec.add_argument("--try-decode", action="store_true", default=True,
                       help="自动尝试用反查到的签名解码")

    # balance
    p_bal = sub.add_parser("balance", help="查询地址余额", parents=[common])
    p_bal.add_argument("address")

    # nonce
    p_non = sub.add_parser("nonce", help="查询 nonce", parents=[common])
    p_non.add_argument("address")

    # raw
    p_raw = sub.add_parser("raw", help="原始 calldata 调用", parents=[common])
    p_raw.add_argument("address")
    p_raw.add_argument("calldata", help="0x 开头的完整 calldata")
    p_raw.add_argument("--write", action="store_true", help="发送写交易（默认是 staticcall）")
    p_raw.add_argument("--key", help="私钥")
    p_raw.add_argument("--keystore", help="keystore 文件")
    p_raw.add_argument("--value", default="0")
    p_raw.add_argument("--gas-limit")
    p_raw.add_argument("--yes", "-y", action="store_true")

    args = parser.parse_args()

    # 跳过 encode/decode 这些不需要 RPC 的命令的连接
    needs_rpc = args.cmd not in ("encode", "decode")

    rpc_url, scanner, native_symbol, _ = resolve_rpc(
        getattr(args, "chain", None),
        getattr(args, "rpc", None),
    )
    args._explorer = scanner.replace("/api", "") if scanner else ""

    if needs_rpc:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            console.print(f"[red]❌ 无法连接 RPC: {rpc_url}[/red]" if HAS_RICH
                          else f"❌ 无法连接 RPC: {rpc_url}")
            sys.exit(1)
        console.print(f"🌐 已连接 [cyan]{rpc_url}[/cyan]  Chain ID: [bold]{w3.eth.chain_id}[/bold]"
                      if HAS_RICH else
                      f"已连接 {rpc_url} (Chain {w3.eth.chain_id})")
    else:
        w3 = Web3()  # 仅用于编码

    # 路由
    if args.cmd == "info":
        cmd_info(args, w3)
    elif args.cmd == "read":
        cmd_read(args, w3)
    elif args.cmd == "call":
        cmd_call(args, w3, native_symbol)
    elif args.cmd == "write":
        cmd_write(args, w3, native_symbol)
    elif args.cmd == "simulate":
        cmd_simulate(args, w3, native_symbol)
    elif args.cmd == "encode":
        cmd_encode(args, w3)
    elif args.cmd == "decode":
        cmd_decode(args, w3)
    elif args.cmd == "balance":
        cmd_balance(args, w3, native_symbol)
    elif args.cmd == "nonce":
        cmd_nonce(args, w3)
    elif args.cmd == "raw":
        cmd_raw(args, w3, native_symbol)


if __name__ == "__main__":
    main()
