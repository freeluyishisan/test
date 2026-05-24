#!/usr/bin/env python3
"""
batch_tx.py —— 批量交易工具
==============================

功能：
  • read       Multicall3 批量读（一笔 RPC 拿几十个返回值）
  • approve    批量 approve（一个 token → 多 spenders / 多 tokens → 一 spender）
  • transfer   批量转账（ERC20 或原生币）
  • run        从 YAML/JSON 配置文件批量发任意交易
  • drain      把一组 ERC20 全部转到指定地址（rug 自救/合并资产）

⚠️ 写交易会真实花 gas。所有命令默认会先模拟，--simulate 只模拟、--yes 跳过确认。

依赖：pip install web3 eth-account pyyaml rich

用法举例：

  # 1) 批量读 ERC20 余额（一次 RPC 调用返回 N 个结果）
  python batch_tx.py read --chain arb \\
      --calls '[
        ["0x6eFa9b8883DFb78fD75CD89d8474C44c3CBDa469", "totalSupply()"],
        ["0x6eFa9b8883DFb78fD75CD89d8474C44c3CBDa469", "name()"],
        ["0x6eFa9b8883DFb78fD75CD89d8474C44c3CBDa469", "decimals()"]
      ]'

  # 2) 批量 approve 同一个 token 给多个 spender
  python batch_tx.py approve --chain arb --key $PK \\
      --token 0xUSDC \\
      --spenders 0xRouter1,0xRouter2,0xRouter3 \\
      --amount "1000 ether"

  # 3) 批量 approve 多个 token 给同一个 spender（典型授权场景）
  python batch_tx.py approve --chain arb --key $PK \\
      --tokens 0xUSDC,0xUSDT,0xDAI \\
      --spender 0xRouter \\
      --amount max

  # 4) 批量空投
  python batch_tx.py transfer --chain arb --key $PK \\
      --token 0xUSDC \\
      --recipients-file ./airdrop.csv  # 每行: addr,amount

  # 5) 把 0xMe 所有 ERC20 转到 0xCold（合并资产 / rug 自救）
  python batch_tx.py drain --chain arb --key $PK \\
      --tokens 0xUSDC,0xUSDT,0xDAI,0xWETH \\
      --to 0xColdWallet

  # 6) 自定义批量配置（最灵活）
  python batch_tx.py run --chain arb --key $PK --config ./batch.yaml
"""

import argparse
import csv
import json
import os
import sys
import time
from typing import Optional

from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3

# 复用 contract_interact.py 的工具函数
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from contract_interact import (  # noqa: E402
    CHAINS, resolve_rpc, function_selector, parse_arg_types,
    parse_value, encode_calldata, load_account, build_tx,
    print_tx_summary, send_tx, static_call, confirm,
    HAS_RICH, console,
)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# Multicall3 (deployed at 同一地址 across all chains)
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
MULTICALL3_AGGREGATE3 = "0x82ad56cb"  # aggregate3((address,bool,bytes)[])

MAX_UINT256 = 2**256 - 1


# ============================================================================
# 批量读：Multicall3
# ============================================================================
def multicall3_aggregate(w3: Web3, calls: list) -> list:
    """
    calls: [(addr, calldata_bytes, allow_failure_bool), ...]
    返回: [(success, return_bytes), ...]
    """
    from eth_abi import encode, decode

    # 构造 aggregate3((address,bool,bytes)[])
    tuples = [(to_checksum_address(addr), bool(allow_fail), data)
              for addr, data, allow_fail in calls]
    encoded_args = encode(["(address,bool,bytes)[]"], [tuples])
    calldata = bytes.fromhex(MULTICALL3_AGGREGATE3[2:]) + encoded_args

    raw = w3.eth.call({"to": MULTICALL3, "data": calldata})
    decoded = decode(["(bool,bytes)[]"], raw)[0]
    return [(s, b) for s, b in decoded]


def cmd_read(args, w3: Web3):
    """批量 read 调用"""
    raw_calls = json.loads(args.calls)  # [[addr, "sig", *args], ...]

    encoded_calls = []
    sigs = []
    for entry in raw_calls:
        addr = entry[0]
        sig = entry[1]
        call_args = entry[2:] if len(entry) > 2 else []
        cd = encode_calldata(sig, call_args, w3)
        encoded_calls.append((addr, cd, True))  # allowFailure=True
        sigs.append(sig)

    console.print(f"\n📞 通过 Multicall3 批量调用 {len(encoded_calls)} 个函数...")
    results = multicall3_aggregate(w3, encoded_calls)

    for i, ((success, retbytes), sig, (addr, _, _)) in enumerate(
        zip(results, sigs, encoded_calls)
    ):
        status = "✅" if success else "❌"
        ret_hex = "0x" + retbytes.hex() if isinstance(retbytes, (bytes, bytearray)) else str(retbytes)
        short = ret_hex[:64] + "..." if len(ret_hex) > 66 else ret_hex
        console.print(f"  [{i+1}] {status} {sig} @ {addr[:10]}...")
        console.print(f"      → {short}")
        if success and len(retbytes) == 32:
            try:
                as_int = int.from_bytes(retbytes, "big")
                console.print(f"      uint: {as_int:,}  |  ÷1e18: {as_int/1e18:.6f}")
            except Exception:
                pass


# ============================================================================
# 批量 approve
# ============================================================================
def cmd_approve(args, w3: Web3, native_symbol: str = "ETH"):
    """批量 approve"""
    account = load_account(args)
    if not account:
        console.print("[red]❌ 需要私钥[/red]" if HAS_RICH else "❌ 需要私钥")
        sys.exit(1)

    # 解析 amount
    if str(args.amount).lower() in ("max", "infinite", "uint256max"):
        amount = MAX_UINT256
    else:
        amount = parse_value("uint256", str(args.amount), w3)

    # 构造 (token, spender) 对列表
    pairs = []
    if args.tokens and args.spender:
        # N tokens × 1 spender
        tokens = [t.strip() for t in args.tokens.split(",")]
        for t in tokens:
            pairs.append((t, args.spender))
    elif args.token and args.spenders:
        # 1 token × N spenders
        spenders = [s.strip() for s in args.spenders.split(",")]
        for s in spenders:
            pairs.append((args.token, s))
    else:
        console.print("[red]❌ 必须指定 (--tokens + --spender) 或 (--token + --spenders)[/red]"
                      if HAS_RICH else "❌ 参数错误")
        sys.exit(1)

    console.print(f"\n📝 即将批量 approve {len(pairs)} 笔，from={account.address}")
    console.print(f"   amount: {amount}")
    for token, spender in pairs:
        console.print(f"   • {token} → {spender}")

    if not args.yes and not args.simulate:
        if not confirm(f"确认发送 {len(pairs)} 笔 approve？"):
            return

    # 顺序发送
    for i, (token, spender) in enumerate(pairs, 1):
        console.print(f"\n--- [{i}/{len(pairs)}] approve {token} → {spender} ---")
        calldata = encode_calldata("approve(address,uint256)", [spender, str(amount)], w3)
        tx = build_tx(w3, account, token, calldata,
                      gas_limit=int(args.gas_limit) if args.gas_limit else None)
        if args.simulate:
            try:
                static_call(w3, token, calldata, sender=account.address)
                console.print(f"[green]✅ 模拟成功[/green]" if HAS_RICH else "✅ 模拟成功")
            except Exception as e:
                console.print(f"[red]❌ 模拟失败：{e}[/red]" if HAS_RICH else f"❌ {e}")
            continue

        try:
            send_tx(w3, account, tx, wait=True)
        except Exception as e:
            console.print(f"[red]❌ tx 失败：{e}[/red]" if HAS_RICH else f"❌ {e}")
            if not args.continue_on_error:
                sys.exit(1)

        # 间隔避免 nonce 抢占
        if i < len(pairs):
            time.sleep(args.delay)


# ============================================================================
# 批量 transfer
# ============================================================================
def cmd_transfer(args, w3: Web3, native_symbol: str = "ETH"):
    """批量转账（ERC20 或原生币）"""
    account = load_account(args)
    if not account:
        console.print("[red]❌ 需要私钥[/red]" if HAS_RICH else "❌ 需要私钥")
        sys.exit(1)

    # 加载收款人列表
    recipients = []  # [(addr, amount_int), ...]
    if args.recipients_file:
        with open(args.recipients_file) as f:
            if args.recipients_file.endswith(".csv"):
                reader = csv.reader(f)
                for row in reader:
                    if not row or row[0].startswith("#"):
                        continue
                    addr = row[0].strip()
                    amt = parse_value("uint256", row[1].strip(), w3)
                    recipients.append((addr, amt))
            elif args.recipients_file.endswith((".json",)):
                data = json.load(f)
                for item in data:
                    addr = item["to"] if isinstance(item, dict) else item[0]
                    amt = item["amount"] if isinstance(item, dict) else item[1]
                    recipients.append((addr, parse_value("uint256", str(amt), w3)))
    elif args.recipients:
        # 命令行格式：--recipients addr1:amount1,addr2:amount2
        for entry in args.recipients.split(","):
            addr, amt = entry.split(":")
            recipients.append((addr.strip(), parse_value("uint256", amt.strip(), w3)))
    else:
        console.print("[red]❌ 必须给 --recipients 或 --recipients-file[/red]"
                      if HAS_RICH else "❌ 参数错误")
        sys.exit(1)

    total = sum(amt for _, amt in recipients)
    console.print(f"\n📤 批量转账：{len(recipients)} 笔，合计 {total}")
    if args.token:
        console.print(f"   代币: {args.token}")
    else:
        console.print(f"   原生币: {native_symbol}")

    for addr, amt in recipients[:5]:
        console.print(f"   • {addr}: {amt}")
    if len(recipients) > 5:
        console.print(f"   ... 还有 {len(recipients) - 5} 笔")

    if not args.yes and not args.simulate:
        if not confirm(f"确认发送 {len(recipients)} 笔？"):
            return

    for i, (addr, amt) in enumerate(recipients, 1):
        console.print(f"\n--- [{i}/{len(recipients)}] {addr} ← {amt} ---")
        if args.token:
            # ERC20 transfer
            calldata = encode_calldata("transfer(address,uint256)", [addr, str(amt)], w3)
            target = args.token
            value = 0
        else:
            # 原生币
            calldata = b""
            target = addr
            value = amt

        tx = build_tx(w3, account, target, calldata, value=value,
                      gas_limit=int(args.gas_limit) if args.gas_limit else None)
        if args.simulate:
            try:
                static_call(w3, target, calldata, sender=account.address, value=value)
                console.print(f"[green]✅ 模拟成功[/green]" if HAS_RICH else "✅ 模拟成功")
            except Exception as e:
                console.print(f"[red]❌ 模拟失败：{e}[/red]" if HAS_RICH else f"❌ {e}")
            continue

        try:
            send_tx(w3, account, tx, wait=True)
        except Exception as e:
            console.print(f"[red]❌ tx 失败：{e}[/red]" if HAS_RICH else f"❌ {e}")
            if not args.continue_on_error:
                sys.exit(1)
        if i < len(recipients):
            time.sleep(args.delay)


# ============================================================================
# drain：把一组代币全部转到指定地址
# ============================================================================
def cmd_drain(args, w3: Web3, native_symbol: str = "ETH"):
    """把多个 ERC20 代币的全部余额转到指定地址（合并 / 救资产）"""
    account = load_account(args)
    if not account:
        console.print("[red]❌ 需要私钥[/red]" if HAS_RICH else "❌ 需要私钥")
        sys.exit(1)

    tokens = [t.strip() for t in args.tokens.split(",")]
    to_addr = to_checksum_address(args.to)

    console.print(f"\n🚿 准备 drain {len(tokens)} 个代币 → {to_addr}")

    # 先 multicall 批量查 balanceOf
    calls = []
    for t in tokens:
        cd = encode_calldata("balanceOf(address)", [account.address], w3)
        calls.append((t, cd, True))
    results = multicall3_aggregate(w3, calls)

    plans = []  # (token, amount)
    for token, (success, ret) in zip(tokens, results):
        if not success or len(ret) < 32:
            console.print(f"   ⚠️  {token}: 查询失败")
            continue
        bal = int.from_bytes(ret, "big")
        if bal == 0:
            console.print(f"   ⏭  {token}: 余额为 0，跳过")
            continue
        plans.append((token, bal))
        console.print(f"   📦 {token}: {bal}")

    if not plans:
        console.print("[yellow]没有任何余额可 drain[/yellow]" if HAS_RICH else "没有余额")
        return

    if args.include_native:
        bal = w3.eth.get_balance(account.address)
        # 留点 gas
        reserved = w3.to_wei(0.001, "ether")
        if bal > reserved:
            plans.append((None, bal - reserved))
            console.print(f"   📦 原生币 {native_symbol}: {w3.from_wei(bal - reserved, 'ether'):.6f}")

    if not args.yes and not args.simulate:
        if not confirm(f"确认把 {len(plans)} 项资产全部 drain 到 {to_addr}？"):
            return

    for i, (token, amt) in enumerate(plans, 1):
        if token is None:
            console.print(f"\n--- [{i}/{len(plans)}] 原生币 {amt} ---")
            tx = build_tx(w3, account, to_addr, b"", value=amt)
        else:
            console.print(f"\n--- [{i}/{len(plans)}] {token} {amt} ---")
            calldata = encode_calldata("transfer(address,uint256)", [to_addr, str(amt)], w3)
            tx = build_tx(w3, account, token, calldata)

        if args.simulate:
            console.print("(simulate, 跳过实发)")
            continue

        try:
            send_tx(w3, account, tx, wait=True)
        except Exception as e:
            console.print(f"[red]❌ {e}[/red]" if HAS_RICH else f"❌ {e}")
            if not args.continue_on_error:
                sys.exit(1)
        if i < len(plans):
            time.sleep(args.delay)


# ============================================================================
# run：从配置文件批量发交易（最灵活）
# ============================================================================
def cmd_run(args, w3: Web3, native_symbol: str = "ETH"):
    """
    YAML 格式：

    txs:
      - to: 0xToken1
        signature: "approve(address,uint256)"
        args: ["0xRouter", "max"]
      - to: 0xRouter
        signature: "swap(uint256,uint256,address[],address)"
        args: ["1000000", "0", ["0xA","0xB"], "0xMe"]
        value: "0.1 ether"
      - to: 0xVault
        signature: "claimRewards()"
        args: []
    """
    account = load_account(args)
    if not account:
        console.print("[red]❌ 需要私钥[/red]" if HAS_RICH else "❌ 需要私钥")
        sys.exit(1)

    with open(args.config) as f:
        if args.config.endswith((".yaml", ".yml")):
            if not HAS_YAML:
                console.print("[red]❌ 需要 pyyaml: pip install pyyaml[/red]"
                              if HAS_RICH else "需要 pyyaml")
                sys.exit(1)
            cfg = yaml.safe_load(f)
        else:
            cfg = json.load(f)

    txs = cfg.get("txs") or cfg.get("transactions") or []
    if not txs:
        console.print("[red]❌ 配置文件没找到 txs 列表[/red]" if HAS_RICH else "❌ 配置错误")
        sys.exit(1)

    console.print(f"\n📋 加载 {len(txs)} 笔交易，from={account.address}")
    for i, t in enumerate(txs, 1):
        console.print(f"  [{i}] → {t['to'][:10]}... {t.get('signature', '<raw>')}")

    if not args.yes and not args.simulate:
        if not confirm(f"确认按顺序发送这 {len(txs)} 笔？"):
            return

    for i, t in enumerate(txs, 1):
        console.print(f"\n=== [{i}/{len(txs)}] {t.get('signature', '<raw>')} → {t['to']} ===")

        # 编码
        if "calldata" in t:
            calldata = bytes.fromhex(t["calldata"].removeprefix("0x"))
        else:
            calldata = encode_calldata(
                t["signature"],
                [str(a) for a in t.get("args", [])],
                w3,
            )
        value = parse_value("uint256", str(t.get("value", "0")), w3)
        gas_limit = int(t["gas_limit"]) if t.get("gas_limit") else None

        tx = build_tx(w3, account, t["to"], calldata, value=value, gas_limit=gas_limit)

        # 模拟兜底
        try:
            static_call(w3, t["to"], calldata, sender=account.address, value=value)
            console.print(f"[green]✅ 模拟通过[/green]" if HAS_RICH else "✅ 模拟通过")
        except Exception as e:
            console.print(f"[red]⚠️ 模拟失败：{str(e)[:120]}[/red]" if HAS_RICH
                          else f"⚠️ {e}")
            if not args.force and not args.simulate:
                console.print("[yellow]跳过此笔（用 --force 强发，--continue-on-error 继续后续）[/yellow]"
                              if HAS_RICH else "跳过此笔")
                if args.continue_on_error:
                    continue
                return

        if args.simulate:
            continue

        try:
            send_tx(w3, account, tx, wait=True)
        except Exception as e:
            console.print(f"[red]❌ {e}[/red]" if HAS_RICH else f"❌ {e}")
            if not args.continue_on_error:
                sys.exit(1)
        if i < len(txs):
            time.sleep(args.delay)


# ============================================================================
# CLI
# ============================================================================
def add_common(p):
    p.add_argument("--rpc")
    p.add_argument("--chain")
    p.add_argument("--key")
    p.add_argument("--keystore")
    p.add_argument("--simulate", action="store_true")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--gas-limit")
    p.add_argument("--delay", type=float, default=1.0, help="每笔之间间隔秒数（默认 1s）")
    p.add_argument("--continue-on-error", action="store_true",
                   help="某笔失败时继续下一笔（默认中止）")


def main():
    parser = argparse.ArgumentParser(description="批量交易工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("read", help="Multicall3 批量 read")
    p1.add_argument("--rpc"); p1.add_argument("--chain")
    p1.add_argument("--calls", required=True,
                    help='JSON 数组：[["addr","sig",arg1,arg2],...]')

    p2 = sub.add_parser("approve", help="批量 approve")
    add_common(p2)
    p2.add_argument("--token", help="单一 token")
    p2.add_argument("--tokens", help="多个 token，逗号分隔")
    p2.add_argument("--spender", help="单一 spender")
    p2.add_argument("--spenders", help="多个 spender，逗号分隔")
    p2.add_argument("--amount", default="max", help="授权数量，'max' 表示无限")
    p2.add_argument("--force", action="store_true")

    p3 = sub.add_parser("transfer", help="批量转账")
    add_common(p3)
    p3.add_argument("--token", help="ERC20 token 地址（不给则发原生币）")
    p3.add_argument("--recipients", help="addr1:amt1,addr2:amt2,...")
    p3.add_argument("--recipients-file", help="CSV/JSON 文件")
    p3.add_argument("--force", action="store_true")

    p4 = sub.add_parser("drain", help="把多个 ERC20 全部转到指定地址")
    add_common(p4)
    p4.add_argument("--tokens", required=True, help="逗号分隔")
    p4.add_argument("--to", required=True)
    p4.add_argument("--include-native", action="store_true",
                    help="也把原生币（留 0.001 gas）一起 drain")
    p4.add_argument("--force", action="store_true")

    p5 = sub.add_parser("run", help="从配置文件按顺序发交易")
    add_common(p5)
    p5.add_argument("--config", required=True, help="YAML/JSON 文件")
    p5.add_argument("--force", action="store_true")

    args = parser.parse_args()

    rpc, scanner, native_symbol, _ = resolve_rpc(
        getattr(args, "chain", None), getattr(args, "rpc", None)
    )
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        console.print(f"[red]❌ 无法连接 {rpc}[/red]" if HAS_RICH else f"❌ 无法连接 {rpc}")
        sys.exit(1)
    console.print(f"🌐 已连接 [cyan]{rpc}[/cyan]  Chain ID: {w3.eth.chain_id}"
                  if HAS_RICH else f"🌐 {rpc}")

    {
        "read":     cmd_read,
        "approve":  cmd_approve,
        "transfer": cmd_transfer,
        "drain":    cmd_drain,
        "run":      cmd_run,
    }[args.cmd](args, w3, native_symbol) if args.cmd != "read" else cmd_read(args, w3)


if __name__ == "__main__":
    main()
