#!/usr/bin/env python3
"""
cast.py —— Foundry cast 兼容 CLI（Python 实现）
==================================================

模仿 Foundry `cast` 的命令风格，让习惯 Foundry 的用户能直接用熟悉的语法。

支持的子命令（与 Foundry cast 一致）：

  调用 / 交易：
    call            cast call <addr> "<sig>" [args...]    （staticcall）
    send            cast send <addr> "<sig>" [args...]    （写交易）
    estimate        cast estimate <addr> "<sig>" [args...]
    publish         cast publish <signed_raw_tx>          （广播已签名交易）

  ABI / 编码：
    abi-encode      cast abi-encode "<sig>" [args...]
    abi-decode      cast abi-decode "<sig>" <data>
    calldata        cast calldata "<sig>" [args...]
    4byte           cast 4byte <selector>                 （反查函数名）
    sig             cast sig "<func>"                     （计算选择器）
    keccak          cast keccak <text>

  数据读取：
    balance         cast balance <addr>
    nonce           cast nonce <addr>
    code            cast code <addr>                      （字节码）
    storage         cast storage <addr> <slot>
    block           cast block <number_or_hash>
    block-number    cast block-number
    chain-id        cast chain-id
    gas-price       cast gas-price
    tx              cast tx <hash>
    receipt         cast receipt <hash>

  转换：
    to-wei          cast to-wei "1.5" eth                 （单位转 wei）
    from-wei        cast from-wei <wei> [unit]
    to-hex          cast to-hex <decimal>
    to-dec          cast to-dec <hex>
    to-checksum     cast to-checksum <addr>
    to-ascii        cast to-ascii <hex>

  地址：
    wallet-new      cast wallet-new                       （生成新地址）
    wallet-address  cast wallet-address --key <pk>

环境变量（同 Foundry）：
  ETH_RPC_URL          RPC URL
  ETH_FROM             默认 from 地址
  ETH_PRIVATE_KEY      私钥
  ETHERSCAN_API_KEY    （未使用，预留）

依赖：pip install web3 eth-account eth-utils rich

例子：

  # 完全跟 Foundry cast 一样
  cast.py call 0xToken "balanceOf(address)" 0xMe --rpc-url $RPC
  cast.py call 0xToken "name()(string)" --rpc-url $RPC
  cast.py send 0xToken "transfer(address,uint256)" 0xRecv "1ether" \\
      --rpc-url $RPC --private-key $PK
  cast.py keccak "transfer(address,uint256)"
  cast.py to-wei "1.5" eth
  cast.py 4byte 0xa9059cbb
  cast.py wallet-new
"""

import argparse
import json
import os
import sys
from typing import Optional

import requests
from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from contract_interact import (  # noqa: E402
    CHAINS, function_selector, parse_arg_types, parse_value, encode_calldata,
    decode_return_value, build_tx, send_tx, static_call, HAS_RICH, console,
)


def get_w3(args) -> Web3:
    """与 Foundry 一致：优先 --rpc-url，再 ETH_RPC_URL，再默认"""
    rpc = (getattr(args, "rpc_url", None)
           or os.getenv("ETH_RPC_URL")
           or "https://arb1.arbitrum.io/rpc")
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        console.print(f"[red]❌ RPC 连接失败: {rpc}[/red]")
        sys.exit(1)
    return w3


def get_account(args) -> Optional[Account]:
    pk = (getattr(args, "private_key", None) or os.getenv("ETH_PRIVATE_KEY"))
    if pk:
        return Account.from_key(pk if pk.startswith("0x") else "0x" + pk)
    keystore = getattr(args, "keystore", None)
    if keystore:
        from getpass import getpass
        with open(os.path.expanduser(keystore)) as f:
            ks = json.load(f)
        pwd = os.getenv("ETH_KEYSTORE_PASSWORD") or getpass("Keystore password: ")
        return Account.from_key(Account.decrypt(ks, pwd))
    return None


# ============================================================================
# 调用 / 交易
# ============================================================================
def cmd_call(args):
    """cast call - staticcall"""
    w3 = get_w3(args)
    addr = to_checksum_address(args.address)
    calldata = encode_calldata(args.signature, args.args, w3)

    sender = args.from_addr or os.getenv("ETH_FROM")
    tx = {"to": addr, "data": calldata, "value": int(args.value or 0)}
    if sender:
        tx["from"] = to_checksum_address(sender)

    try:
        result = w3.eth.call(tx, args.block or "latest")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # 输出风格模仿 cast：默认裸 hex
    if args.json:
        decoded = decode_return_value(args.signature, result)
        print(json.dumps({
            "raw": "0x" + result.hex(),
            "decoded": str(decoded) if decoded else None,
        }, indent=2))
    else:
        if "returns" in args.signature or "(" in args.signature.split(")", 1)[-1]:
            decoded = decode_return_value(args.signature, result)
            if decoded is not None and not isinstance(decoded, bytes):
                print(decoded if not isinstance(decoded, tuple) or len(decoded) > 1 else decoded[0])
                return
        # default: hex
        print("0x" + result.hex())


def cmd_send(args):
    """cast send - 真实发交易"""
    w3 = get_w3(args)
    account = get_account(args)
    if not account:
        console.print("[red]❌ 需要 --private-key 或 --keystore 或 ETH_PRIVATE_KEY 环境变量[/red]")
        sys.exit(1)

    addr = to_checksum_address(args.address)
    calldata = encode_calldata(args.signature, args.args, w3)
    value = parse_value("uint256", args.value or "0", w3)

    tx = build_tx(w3, account, addr, calldata, value=value,
                  gas_limit=int(args.gas_limit) if args.gas_limit else None,
                  gas_price_gwei=float(args.gas_price) if args.gas_price else None)

    if args.legacy:
        tx.pop("maxFeePerGas", None)
        tx.pop("maxPriorityFeePerGas", None)
        tx["type"] = 0
        if "gasPrice" not in tx:
            tx["gasPrice"] = w3.eth.gas_price

    if not args.confirm:
        console.print(f"📝 sending tx → {addr}")
        console.print(f"   gas: {tx['gas']:,}, value: {value} wei")

    try:
        result = send_tx(w3, account, tx, wait=not args.async_send)
        if args.json:
            print(json.dumps({
                "transactionHash": result.tx_hash,
                "blockNumber": result.block_number,
                "gasUsed": result.gas_used,
                "status": result.status,
            }))
        else:
            print(result.tx_hash)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def cmd_estimate(args):
    """cast estimate - 估 gas"""
    w3 = get_w3(args)
    addr = to_checksum_address(args.address)
    calldata = encode_calldata(args.signature, args.args, w3)
    sender = args.from_addr or os.getenv("ETH_FROM")
    if not sender:
        account = get_account(args)
        sender = account.address if account else None

    tx = {"to": addr, "data": calldata, "value": int(args.value or 0)}
    if sender:
        tx["from"] = to_checksum_address(sender)

    try:
        gas = w3.eth.estimate_gas(tx)
        print(gas)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def cmd_publish(args):
    """cast publish - 广播已签名的 raw tx"""
    w3 = get_w3(args)
    raw = bytes.fromhex(args.raw_tx.removeprefix("0x"))
    h = w3.eth.send_raw_transaction(raw)
    print("0x" + h.hex())


# ============================================================================
# ABI / 编码
# ============================================================================
def cmd_abi_encode(args):
    """cast abi-encode - 只编码参数（不带 selector）"""
    from eth_abi import encode
    w3 = Web3()
    types = parse_arg_types(args.signature)
    parsed = [parse_value(t, v, w3) for t, v in zip(types, args.args)]
    encoded = encode(types, parsed)
    print("0x" + encoded.hex())


def cmd_abi_decode(args):
    """cast abi-decode - 解码"""
    from eth_abi import decode
    types = parse_arg_types(args.signature)
    raw = bytes.fromhex(args.data.removeprefix("0x"))
    # 如果开头有 selector（4 字节），可选剥离
    if args.from_calldata and len(raw) >= 4:
        raw = raw[4:]
    try:
        decoded = decode(types, raw)
        for d in decoded:
            print(d)
    except Exception as e:
        console.print(f"[red]Decode error: {e}[/red]")
        sys.exit(1)


def cmd_calldata(args):
    """cast calldata - 编码完整 calldata（selector + args）"""
    w3 = Web3()
    cd = encode_calldata(args.signature, args.args, w3)
    print("0x" + cd.hex())


def cmd_4byte(args):
    """cast 4byte - 反查函数名"""
    sel = args.selector.lower()
    if not sel.startswith("0x"):
        sel = "0x" + sel
    try:
        r = requests.get(
            f"https://api.openchain.xyz/signature-database/v1/lookup?function={sel}",
            timeout=8,
        )
        data = r.json().get("result", {}).get("function", {}).get(sel, [])
        if not data:
            r2 = requests.get(
                f"https://www.4byte.directory/api/v1/signatures/?hex_signature={sel}",
                timeout=8,
            )
            data = [{"name": x["text_signature"]} for x in r2.json().get("results", [])]
        if not data:
            print(f"未找到 {sel} 对应的签名")
            sys.exit(1)
        for item in data:
            print(item.get("name", item))
    except Exception as e:
        console.print(f"[red]反查失败: {e}[/red]")
        sys.exit(1)


def cmd_sig(args):
    """cast sig - 计算 selector"""
    print("0x" + function_selector(args.signature).hex())


def cmd_keccak(args):
    """cast keccak - keccak256 hash"""
    text = args.text
    if text.startswith("0x"):
        data = bytes.fromhex(text[2:])
        h = keccak(data)
    else:
        h = keccak(text=text)
    print("0x" + h.hex())


# ============================================================================
# 数据读取
# ============================================================================
def cmd_balance(args):
    w3 = get_w3(args)
    bal = w3.eth.get_balance(to_checksum_address(args.address), args.block or "latest")
    if args.ether:
        print(w3.from_wei(bal, "ether"))
    else:
        print(bal)


def cmd_nonce(args):
    w3 = get_w3(args)
    n = w3.eth.get_transaction_count(to_checksum_address(args.address), args.block or "latest")
    print(n)


def cmd_code(args):
    w3 = get_w3(args)
    code = w3.eth.get_code(to_checksum_address(args.address), args.block or "latest")
    print("0x" + code.hex())


def cmd_storage(args):
    w3 = get_w3(args)
    slot = int(args.slot, 0) if args.slot.startswith("0x") else int(args.slot)
    val = w3.eth.get_storage_at(to_checksum_address(args.address), slot,
                                args.block or "latest")
    print("0x" + val.hex())


def cmd_block(args):
    w3 = get_w3(args)
    blk_id = args.block_id
    if blk_id.isdigit():
        blk_id = int(blk_id)
    elif blk_id.startswith("0x") and len(blk_id) == 66:
        pass  # block hash
    elif blk_id.lower() in ("latest", "earliest", "pending", "safe", "finalized"):
        pass
    else:
        try:
            blk_id = int(blk_id)
        except Exception:
            pass
    blk = w3.eth.get_block(blk_id, full_transactions=args.full)
    print(json.dumps({
        "number": blk.number,
        "hash": blk.hash.hex(),
        "timestamp": blk.timestamp,
        "miner": blk.miner,
        "gasUsed": blk.gasUsed,
        "gasLimit": blk.gasLimit,
        "baseFeePerGas": blk.get("baseFeePerGas", None),
        "transactions": len(blk.transactions),
    }, indent=2, default=str))


def cmd_block_number(args):
    w3 = get_w3(args)
    print(w3.eth.block_number)


def cmd_chain_id(args):
    w3 = get_w3(args)
    print(w3.eth.chain_id)


def cmd_gas_price(args):
    w3 = get_w3(args)
    gp = w3.eth.gas_price
    if args.gwei:
        print(w3.from_wei(gp, "gwei"))
    else:
        print(gp)


def cmd_tx(args):
    w3 = get_w3(args)
    tx = w3.eth.get_transaction(args.hash)
    print(json.dumps(dict(tx), indent=2, default=str))


def cmd_receipt(args):
    w3 = get_w3(args)
    r = w3.eth.get_transaction_receipt(args.hash)
    print(json.dumps(dict(r), indent=2, default=str))


# ============================================================================
# 转换
# ============================================================================
def cmd_to_wei(args):
    w3 = Web3()
    print(w3.to_wei(args.value, args.unit or "ether"))


def cmd_from_wei(args):
    w3 = Web3()
    print(w3.from_wei(int(args.value), args.unit or "ether"))


def cmd_to_hex(args):
    val = int(args.value)
    print(hex(val))


def cmd_to_dec(args):
    print(int(args.value, 16))


def cmd_to_checksum(args):
    print(to_checksum_address(args.address))


def cmd_to_ascii(args):
    raw = bytes.fromhex(args.hex.removeprefix("0x"))
    # 把零字节去掉
    print(raw.rstrip(b"\x00").decode("utf-8", errors="replace"))


# ============================================================================
# 钱包
# ============================================================================
def cmd_wallet_new(args):
    """生成新随机钱包"""
    acct = Account.create()
    print(f"Address:     {acct.address}")
    print(f"Private key: 0x{acct.key.hex()}")
    if HAS_RICH:
        console.print("\n[yellow]⚠️ 妥善保管私钥！[/yellow]")


def cmd_wallet_address(args):
    """从私钥推导地址"""
    pk = args.private_key or os.getenv("ETH_PRIVATE_KEY")
    if not pk:
        console.print("[red]❌ 需要 --private-key 或 ETH_PRIVATE_KEY[/red]")
        sys.exit(1)
    if not pk.startswith("0x"):
        pk = "0x" + pk
    print(Account.from_key(pk).address)


# ============================================================================
# CLI
# ============================================================================
def add_rpc_args(p):
    p.add_argument("--rpc-url", "-r", help="RPC URL（也可用环境变量 ETH_RPC_URL）")


def add_send_args(p):
    add_rpc_args(p)
    p.add_argument("--private-key", "-k", help="私钥（也可用 ETH_PRIVATE_KEY）")
    p.add_argument("--keystore", help="keystore 文件")
    p.add_argument("--from", dest="from_addr", help="from 地址")
    p.add_argument("--value", "-v", help="附带的 ETH 数量")
    p.add_argument("--gas-limit")
    p.add_argument("--gas-price")
    p.add_argument("--legacy", action="store_true", help="使用 legacy gas 模式")


def main():
    parser = argparse.ArgumentParser(
        description="Foundry cast 兼容 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # call
    p = sub.add_parser("call", help="调用 view 函数")
    add_rpc_args(p)
    p.add_argument("address"); p.add_argument("signature"); p.add_argument("args", nargs="*")
    p.add_argument("--from", dest="from_addr"); p.add_argument("--value")
    p.add_argument("--block", "-b"); p.add_argument("--json", action="store_true")

    # send
    p = sub.add_parser("send", help="发送交易")
    add_send_args(p)
    p.add_argument("address"); p.add_argument("signature"); p.add_argument("args", nargs="*")
    p.add_argument("--async-send", action="store_true", help="不等待 receipt")
    p.add_argument("--confirm", action="store_true", help="不打印 summary 直接发")
    p.add_argument("--json", action="store_true")

    # estimate
    p = sub.add_parser("estimate", help="估算 gas")
    add_rpc_args(p)
    p.add_argument("address"); p.add_argument("signature"); p.add_argument("args", nargs="*")
    p.add_argument("--from", dest="from_addr")
    p.add_argument("--private-key", "-k"); p.add_argument("--keystore")
    p.add_argument("--value")

    # publish
    p = sub.add_parser("publish", help="广播已签名的 raw tx")
    add_rpc_args(p)
    p.add_argument("raw_tx")

    # abi-encode
    p = sub.add_parser("abi-encode", help="ABI 编码（不带 selector）")
    p.add_argument("signature"); p.add_argument("args", nargs="*")

    # abi-decode
    p = sub.add_parser("abi-decode", help="ABI 解码")
    p.add_argument("signature"); p.add_argument("data")
    p.add_argument("--from-calldata", action="store_true", help="data 是带 selector 的 calldata")

    # calldata
    p = sub.add_parser("calldata", help="编码完整 calldata（含 selector）")
    p.add_argument("signature"); p.add_argument("args", nargs="*")

    # 4byte
    p = sub.add_parser("4byte", help="根据 selector 反查函数名")
    p.add_argument("selector")

    # sig
    p = sub.add_parser("sig", help="计算函数签名的 selector")
    p.add_argument("signature")

    # keccak
    p = sub.add_parser("keccak", help="keccak256 hash")
    p.add_argument("text")

    # balance
    p = sub.add_parser("balance", help="查地址余额")
    add_rpc_args(p)
    p.add_argument("address"); p.add_argument("--block", "-b")
    p.add_argument("--ether", "-e", action="store_true", help="以 ether 为单位输出")

    # nonce
    p = sub.add_parser("nonce", help="查 nonce")
    add_rpc_args(p)
    p.add_argument("address"); p.add_argument("--block", "-b")

    # code
    p = sub.add_parser("code", help="查地址字节码")
    add_rpc_args(p)
    p.add_argument("address"); p.add_argument("--block", "-b")

    # storage
    p = sub.add_parser("storage", help="读 storage slot")
    add_rpc_args(p)
    p.add_argument("address"); p.add_argument("slot"); p.add_argument("--block", "-b")

    # block
    p = sub.add_parser("block", help="查 block 信息")
    add_rpc_args(p)
    p.add_argument("block_id"); p.add_argument("--full", action="store_true")

    # block-number / chain-id / gas-price
    p = sub.add_parser("block-number"); add_rpc_args(p)
    p = sub.add_parser("chain-id"); add_rpc_args(p)
    p = sub.add_parser("gas-price"); add_rpc_args(p)
    p.add_argument("--gwei", action="store_true")

    # tx / receipt
    p = sub.add_parser("tx", help="查交易详情"); add_rpc_args(p); p.add_argument("hash")
    p = sub.add_parser("receipt", help="查交易回执"); add_rpc_args(p); p.add_argument("hash")

    # 转换
    p = sub.add_parser("to-wei", help="单位转 wei")
    p.add_argument("value"); p.add_argument("unit", nargs="?", default="ether")
    p = sub.add_parser("from-wei", help="wei 转单位")
    p.add_argument("value"); p.add_argument("unit", nargs="?", default="ether")
    p = sub.add_parser("to-hex", help="十进制转 hex"); p.add_argument("value")
    p = sub.add_parser("to-dec", help="hex 转十进制"); p.add_argument("value")
    p = sub.add_parser("to-checksum", help="转 checksum 地址"); p.add_argument("address")
    p = sub.add_parser("to-ascii", help="hex 转 ASCII"); p.add_argument("hex")

    # 钱包
    sub.add_parser("wallet-new", help="生成新随机钱包")
    p = sub.add_parser("wallet-address", help="从私钥导出地址")
    p.add_argument("--private-key", "-k")

    args = parser.parse_args()

    routes = {
        "call":           cmd_call,
        "send":           cmd_send,
        "estimate":       cmd_estimate,
        "publish":        cmd_publish,
        "abi-encode":     cmd_abi_encode,
        "abi-decode":     cmd_abi_decode,
        "calldata":       cmd_calldata,
        "4byte":          cmd_4byte,
        "sig":            cmd_sig,
        "keccak":         cmd_keccak,
        "balance":        cmd_balance,
        "nonce":          cmd_nonce,
        "code":           cmd_code,
        "storage":        cmd_storage,
        "block":          cmd_block,
        "block-number":   cmd_block_number,
        "chain-id":       cmd_chain_id,
        "gas-price":      cmd_gas_price,
        "tx":             cmd_tx,
        "receipt":        cmd_receipt,
        "to-wei":         cmd_to_wei,
        "from-wei":       cmd_from_wei,
        "to-hex":         cmd_to_hex,
        "to-dec":         cmd_to_dec,
        "to-checksum":    cmd_to_checksum,
        "to-ascii":       cmd_to_ascii,
        "wallet-new":     cmd_wallet_new,
        "wallet-address": cmd_wallet_address,
    }
    routes[args.cmd](args)


if __name__ == "__main__":
    main()
