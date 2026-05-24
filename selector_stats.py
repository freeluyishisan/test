#!/usr/bin/env python3
"""
selector_stats.py —— 选择器频率统计 / 全网热点分析

功能：
  • topbatch    批量分析多个合约的选择器，统计哪些函数最常见
  • find_addr   找全网部署过同字节码的合约（用于跨链找开源版本）
  • crosschain  对比同一合约在多链的字节码差异

依赖：pip install web3 requests
"""

import argparse
import re
import json
from collections import Counter
from web3 import Web3


def extract_selectors(code: bytes) -> set:
    sels = set()
    for pat in (rb'\x80\x63(.{4})\x14\x61.{2}\x57', rb'\x80\x63(.{4})\x14\x62.{3}\x57'):
        for m in re.finditer(pat, code, re.DOTALL):
            sels.add("0x" + m.group(1).hex())
    return sels


def cmd_topbatch(args):
    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print(f"❌ RPC 连接失败: {args.rpc}")
        return

    counter = Counter()
    contract_count = 0

    with open(args.addresses) as f:
        addrs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"📊 批量分析 {len(addrs)} 个合约的选择器...")

    for addr in addrs:
        try:
            code = w3.eth.get_code(Web3.to_checksum_address(addr))
            if not code or len(code) < 10:
                continue
            sels = extract_selectors(bytes(code))
            counter.update(sels)
            contract_count += 1
            print(f"  ✓ {addr}: {len(sels)} 个函数")
        except Exception as e:
            print(f"  ✗ {addr}: {e}")

    print(f"\n=== 选择器频率排行 (Top {args.top}) ===\n")
    print(f"{'排名':<6}{'选择器':<14}{'出现次数':<10}{'占比':<8}{'函数名（猜测）'}")
    print("-" * 80)

    # 反查
    import requests
    for i, (sel, count) in enumerate(counter.most_common(args.top), 1):
        names = []
        try:
            r = requests.get(
                f"https://api.openchain.xyz/signature-database/v1/lookup?function={sel}",
                timeout=3,
            )
            data = r.json().get("result", {}).get("function", {}).get(sel, [])
            names = [item["name"] for item in data[:2]]
        except Exception:
            pass
        pct = count / contract_count * 100
        name_str = " | ".join(names) if names else "【未知】"
        print(f"{i:<6}{sel:<14}{count:<10}{pct:<7.1f}% {name_str}")


def cmd_find_addr(args):
    """根据字节码 hash，找还有哪些合约部署了一样的字节码"""
    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print(f"❌ RPC 连接失败")
        return

    code = w3.eth.get_code(Web3.to_checksum_address(args.address))
    code_hash = Web3.keccak(code).hex()
    print(f"📦 合约 {args.address}")
    print(f"   字节码大小: {len(code)} 字节")
    print(f"   字节码 keccak256: {code_hash}")
    print(f"\n💡 在 Sourcify 上查找同字节码合约:")
    print(f"   https://repo.sourcify.dev/select-contract/?codehash={code_hash}")
    print(f"\n💡 也可以试 Bytegraph:")
    print(f"   https://bytegraph.xyz/contract/{args.address}")


def cmd_crosschain(args):
    """对比同一地址在多链的字节码"""
    chains = {
        "eth":     "https://eth.llamarpc.com",
        "arb":     "https://arb1.arbitrum.io/rpc",
        "op":      "https://mainnet.optimism.io",
        "base":    "https://mainnet.base.org",
        "bsc":     "https://bsc-dataseed.binance.org",
        "polygon": "https://polygon-rpc.com",
    }

    print(f"\n🔍 在 {len(chains)} 条链上查询合约 {args.address} 的字节码...\n")
    results = {}
    for name, rpc in chains.items():
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 8}))
            if not w3.is_connected():
                results[name] = "RPC 连接失败"
                continue
            code = w3.eth.get_code(Web3.to_checksum_address(args.address))
            if not code:
                results[name] = "未部署"
            else:
                hash_str = Web3.keccak(code).hex()[:18] + "..."
                results[name] = f"{len(code)} 字节  hash={hash_str}"
        except Exception as e:
            results[name] = f"错误: {str(e)[:40]}"

    for name, status in results.items():
        print(f"  {name:<10} → {status}")


def main():
    parser = argparse.ArgumentParser(description="选择器统计与跨链对比")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("topbatch", help="批量分析选择器频率")
    p1.add_argument("addresses", help="包含合约地址的文本文件，每行一个")
    p1.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")
    p1.add_argument("--top", type=int, default=30)

    p2 = sub.add_parser("find_addr", help="找还有哪些合约部署了同样的字节码")
    p2.add_argument("address")
    p2.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")

    p3 = sub.add_parser("crosschain", help="同一地址在多链查询字节码")
    p3.add_argument("address")

    args = parser.parse_args()
    if args.cmd == "topbatch":
        cmd_topbatch(args)
    elif args.cmd == "find_addr":
        cmd_find_addr(args)
    elif args.cmd == "crosschain":
        cmd_crosschain(args)


if __name__ == "__main__":
    main()
