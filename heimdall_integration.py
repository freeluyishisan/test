#!/usr/bin/env python3
"""
heimdall_integration.py —— Heimdall 反编译集成

封装 Heimdall CLI 调用，把字节码反编译成近似 Solidity 源码。

依赖：
  必须先安装 Heimdall：
    cargo install --git https://github.com/Jon-Becker/heimdall-rs heimdall

用法：
  python heimdall_integration.py decompile 0x68d319... --rpc https://...
  python heimdall_integration.py disasm 0x68d319...
  python heimdall_integration.py cfg 0x68d319...
"""

import argparse
import shutil
import subprocess
import sys


def check_heimdall():
    """检查 heimdall 是否可用"""
    if not shutil.which("heimdall"):
        print("❌ 未找到 heimdall 命令。请先安装：")
        print("   cargo install --git https://github.com/Jon-Becker/heimdall-rs heimdall")
        print("\n或者用 Docker:")
        print("   docker pull jonbecker/heimdall-rs")
        sys.exit(1)


def run(cmd_list):
    print(f"🔧 执行: {' '.join(cmd_list)}\n")
    result = subprocess.run(cmd_list, capture_output=False)
    if result.returncode != 0:
        print(f"\n❌ 命令失败 (exit {result.returncode})")
        sys.exit(result.returncode)


def cmd_decompile(args):
    check_heimdall()
    cmd = ["heimdall", "decompile",
           "--rpc-url", args.rpc,
           args.address]
    if args.output:
        cmd += ["--output", args.output]
    if args.skip_resolving:
        cmd += ["--skip-resolving"]
    if args.include_solidity:
        cmd += ["--include-solidity"]
    if args.include_yul:
        cmd += ["--include-yul"]
    run(cmd)


def cmd_disasm(args):
    check_heimdall()
    cmd = ["heimdall", "disassemble", "--rpc-url", args.rpc, args.address]
    run(cmd)


def cmd_cfg(args):
    check_heimdall()
    cmd = ["heimdall", "cfg", "--rpc-url", args.rpc, args.address]
    if args.output:
        cmd += ["--output", args.output]
    run(cmd)


def cmd_inspect(args):
    """inspect tx：查看一笔交易的详细执行轨迹"""
    check_heimdall()
    cmd = ["heimdall", "inspect", "--rpc-url", args.rpc, args.tx_hash]
    run(cmd)


def main():
    parser = argparse.ArgumentParser(description="Heimdall 反编译工具集成")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("decompile", help="反编译合约成近似 Solidity")
    p1.add_argument("address")
    p1.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")
    p1.add_argument("--output", "-o", help="输出目录")
    p1.add_argument("--skip-resolving", action="store_true", help="跳过函数名反查（更快）")
    p1.add_argument("--include-solidity", action="store_true", default=True)
    p1.add_argument("--include-yul", action="store_true", help="同时输出 Yul 代码")

    p2 = sub.add_parser("disasm", help="反汇编字节码")
    p2.add_argument("address")
    p2.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")

    p3 = sub.add_parser("cfg", help="生成控制流图")
    p3.add_argument("address")
    p3.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")
    p3.add_argument("--output", "-o")

    p4 = sub.add_parser("inspect", help="检查一笔交易的执行轨迹")
    p4.add_argument("tx_hash")
    p4.add_argument("--rpc", default="https://arb1.arbitrum.io/rpc")

    args = parser.parse_args()
    {"decompile": cmd_decompile, "disasm": cmd_disasm,
     "cfg": cmd_cfg, "inspect": cmd_inspect}[args.cmd](args)


if __name__ == "__main__":
    main()
