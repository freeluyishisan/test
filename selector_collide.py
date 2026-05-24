#!/usr/bin/env python3
"""
selector_collide.py —— 函数选择器碰撞构造工具
================================================

功能：
  • find    给定一个目标 selector，暴力爆破能撞上它的"假函数名"
  • check   检查一个签名是否会和已知敏感函数碰撞
  • compare 对比两个合约的选择器集合，找冲突

⚠️ 这是 **进攻向** 工具，可用于：
  • 红队测试代理合约的 Audius-style 漏洞
  • 验证你自己合约的代理 + 实现是否会冲突
  • 学习"主动选择器碰撞攻击"原理

依赖：仅 eth_utils + 标准库

用法：
  # 找一个能撞上 transfer(address,uint256) 选择器的"看起来像审计/治理"的函数名
  python selector_collide.py find 0xa9059cbb \\
      --templates "init,upgrade,changeImpl,setOwner" \\
      --max 5000000

  # 检查某个签名碰撞情况
  python selector_collide.py check "transferOwnership(address)"

  # 对比两个合约
  python selector_collide.py compare 0xProxy 0xImpl --rpc https://...
"""

import argparse
import itertools
import string
import sys
import time

from eth_utils import keccak


def selector_of(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()


def cmd_check(args):
    """显示一个签名的选择器，及其潜在碰撞"""
    sig = args.signature
    sel = selector_of(sig)
    print(f"\n📌 签名: {sig}")
    print(f"   选择器: {sel}")
    print(f"\n💡 在 4byte / Openchain 上反查这个选择器，看看有没有恶意签名占用同一空间：")
    print(f"   https://www.4byte.directory/signatures/?bytes4_signature={sel}")
    print(f"   https://api.openchain.xyz/signature-database/v1/lookup?function={sel}")


def cmd_find(args):
    """
    暴力构造一个能撞上指定 selector 的"看起来合法"的函数名。

    策略：
      function_name + (param_types) → keccak[:4] == target_selector
      我们尝试在 function_name 上加一些"random salt 后缀"做爆破。
    """
    target = args.selector.lower().removeprefix("0x")
    if len(target) != 8:
        print(f"❌ selector 必须是 8 位 hex（4 字节），收到: {args.selector}")
        sys.exit(1)
    target_bytes = bytes.fromhex(target)

    templates = [t.strip() for t in args.templates.split(",") if t.strip()]
    param_sets = [p.strip() for p in args.params.split("|") if p.strip()]

    print(f"\n🎯 目标 selector: 0x{target}")
    print(f"   候选函数名前缀: {templates}")
    print(f"   候选参数列表:   {param_sets}")
    print(f"   最大尝试次数:   {args.max:,}\n")

    chars = string.ascii_lowercase + string.digits
    start = time.time()
    found = []

    # 用增长长度的爆破（短的先试）
    for suffix_len in range(1, 12):
        if len(found) >= args.count:
            break
        # 第 N 长的所有 a-z0-9 组合
        attempted = 0
        for suffix_tuple in itertools.product(chars, repeat=suffix_len):
            suffix = "".join(suffix_tuple)
            for tpl in templates:
                for params in param_sets:
                    candidate = f"{tpl}_{suffix}({params})"
                    if keccak(text=candidate)[:4] == target_bytes:
                        elapsed = time.time() - start
                        print(f"✅ 找到碰撞！候选签名: \033[1;32m{candidate}\033[0m")
                        print(f"   (耗时 {elapsed:.1f}s)")
                        found.append(candidate)
                        if len(found) >= args.count:
                            break
            if len(found) >= args.count:
                break
            attempted += 1
            if attempted >= args.max:
                break
        if attempted >= args.max:
            break
        elapsed = time.time() - start
        print(f"  尝试完 {suffix_len} 字符后缀（用时 {elapsed:.1f}s），还没撞到...")

    if not found:
        print(f"\n⚠️ 在 {args.max:,} 次尝试内没找到碰撞。"
              f"\n   提示：扩大 templates / params，或增大 --max")
    else:
        print(f"\n📊 找到 {len(found)} 个碰撞候选签名。这些签名计算后的选择器都等于 0x{target}")


def cmd_compare(args):
    """比较两个合约的 dispatcher 选择器，找冲突"""
    from web3 import Web3
    import re

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print(f"❌ 无法连接 RPC: {args.rpc}")
        sys.exit(1)

    def extract(addr):
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(addr)))
        # 严格 dispatcher 模式
        sels = set()
        for pat in (rb'\x80\x63(.{4})\x14\x61.{2}\x57', rb'\x80\x63(.{4})\x14\x62.{3}\x57'):
            for m in re.finditer(pat, code, re.DOTALL):
                sels.add("0x" + m.group(1).hex())
        return sels

    sels_a = extract(args.contract_a)
    sels_b = extract(args.contract_b)
    overlap = sels_a & sels_b
    only_a = sels_a - sels_b
    only_b = sels_b - sels_a

    print(f"\n📦 合约 A: {args.contract_a}  → {len(sels_a)} 个函数")
    print(f"📦 合约 B: {args.contract_b}  → {len(sels_b)} 个函数")
    print(f"\n🔁 共同选择器: {len(overlap)}")
    if overlap:
        print(f"\n⚠️  以下选择器在两个合约都存在（可能是 Audius-style 漏洞前置条件）:")
        for s in sorted(overlap):
            print(f"   • {s}")
    print(f"\n仅 A 有: {len(only_a)} 个")
    print(f"仅 B 有: {len(only_b)} 个")


def main():
    parser = argparse.ArgumentParser(
        description="函数选择器碰撞工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="计算签名的选择器")
    p_check.add_argument("signature", help='如 "transfer(address,uint256)"')

    p_find = sub.add_parser("find", help="暴力爆破能撞上目标 selector 的函数名")
    p_find.add_argument("selector", help="目标 selector，如 0xa9059cbb")
    p_find.add_argument("--templates", default="init,upgrade,setOwner,grant,collect,exec",
                        help="候选函数名前缀（逗号分隔）")
    p_find.add_argument("--params", default="|address|uint256|address,uint256|bytes",
                        help="候选参数列表组合（| 分隔）。空字符串 '' 表示无参数")
    p_find.add_argument("--max", type=int, default=5_000_000, help="单段后缀最大尝试次数")
    p_find.add_argument("--count", type=int, default=3, help="找到 N 个就停")

    p_cmp = sub.add_parser("compare", help="对比两个合约的选择器")
    p_cmp.add_argument("contract_a")
    p_cmp.add_argument("contract_b")
    p_cmp.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")

    args = parser.parse_args()

    if args.cmd == "check":
        cmd_check(args)
    elif args.cmd == "find":
        cmd_find(args)
    elif args.cmd == "compare":
        cmd_compare(args)


if __name__ == "__main__":
    main()
