#!/usr/bin/env python3
"""
flashloan.py —— 闪电贷集成（Aave V3 / Balancer V2）
======================================================

功能：
  • info       显示 Aave / Balancer 池子地址 + 借款手续费
  • encode     生成 flashLoan 的 calldata（不发送）
  • call       发送 flashLoan 交易（要求已部署 receiver 合约）
  • generate   生成一份通用 receiver Solidity 合约模板
  • simulate   用 eth_call 模拟 flashLoan 调用

⚠️ 闪电贷是高级功能，需要：
  1) 一个 **receiver 合约**（实现 IFlashLoanReceiver / IFlashLoanRecipient）
     —— 不能直接对 EOA 用闪电贷，因为 callback 必须是合约
  2) Receiver 合约里写好「借到币之后要做什么」（套利/清算/还债...）
  3) 必须在 callback 结束前把币 + 手续费还回去

本工具帮你：
  - 生成 receiver 模板（generate）
  - 编 / 发 flashLoan calldata（encode/call）
  - 在你 receiver 部署后用 Python 触发

依赖：pip install web3 eth-account eth-abi rich

用法：

  # 1) 看支持哪些链 / 池子地址 / 手续费
  python flashloan.py info --chain arb

  # 2) 生成一份通用 receiver 合约模板（Solidity）
  python flashloan.py generate --provider aave --output ./MyFlashLoan.sol

  # 3) 编 calldata（不发送）—— Aave V3 单资产
  python flashloan.py encode --provider aave \\
      --receiver 0xYourDeployedReceiver \\
      --asset 0xUSDC --amount "1000 ether" \\
      --params 0x   # 传给 receiver 的 user data

  # 4) 真发起闪电贷
  python flashloan.py call --provider balancer --chain arb --key $PK \\
      --receiver 0xYourReceiver \\
      --tokens 0xUSDC,0xWETH --amounts "1000 ether","0.5 ether" \\
      --params 0xabcd...
"""

import argparse
import json
import os
import sys
from typing import Optional

from eth_account import Account
from eth_utils import keccak, to_checksum_address
from web3 import Web3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from contract_interact import (  # noqa: E402
    CHAINS, resolve_rpc, parse_value, encode_calldata, load_account,
    build_tx, print_tx_summary, send_tx, static_call, confirm,
    HAS_RICH, console,
)


# ============================================================================
# Provider 配置
# ============================================================================
# Aave V3 Pool 地址（多链）
AAVE_V3_POOL = {
    "eth":     "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "arb":     "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "op":      "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "polygon": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "avax":    "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "base":    "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
    "scroll":  "0x11fCfe756c05AD438e312a7fd934381537D3cFfe",
}

# Balancer V2 Vault（同一地址 across 所有链）
BALANCER_V2_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"

# Aave 闪电贷手续费（默认 5 bps = 0.05%）
AAVE_FLASHLOAN_PREMIUM_BPS = 5
# Balancer 手续费（0%！）
BALANCER_FLASHLOAN_PREMIUM_BPS = 0


# ============================================================================
# 命令实现
# ============================================================================
def cmd_info(args, w3: Web3 = None):
    """显示池子地址 + 手续费"""
    chain = args.chain or "arb"
    aave_pool = AAVE_V3_POOL.get(chain.lower(), "（该链未提供）")

    console.print(f"\n💎 [bold]Flashloan Provider 信息[/bold] (链: {chain})\n" if HAS_RICH
                  else f"\n=== Flashloan Providers ({chain}) ===\n")
    console.print(f"📌 [bold]Aave V3[/bold]")
    console.print(f"   Pool 地址: [cyan]{aave_pool}[/cyan]")
    console.print(f"   手续费:   {AAVE_FLASHLOAN_PREMIUM_BPS} bps (0.05%)")
    console.print(f"   接口:     [yellow]flashLoan(receiver, assets[], amounts[], modes[], onBehalfOf, params, referralCode)[/yellow]"
                  if HAS_RICH else
                  "   接口: flashLoan(...)")
    console.print(f"   Receiver 必须实现: [yellow]executeOperation()[/yellow]\n")

    console.print(f"📌 [bold]Balancer V2[/bold] (推荐！0 手续费)")
    console.print(f"   Vault 地址: [cyan]{BALANCER_V2_VAULT}[/cyan]")
    console.print(f"   手续费:    {BALANCER_FLASHLOAN_PREMIUM_BPS} bps")
    console.print(f"   接口:      [yellow]flashLoan(recipient, tokens[], amounts[], userData)[/yellow]"
                  if HAS_RICH else "   接口: flashLoan(...)")
    console.print(f"   Recipient 必须实现: [yellow]receiveFlashLoan()[/yellow]\n")

    console.print("⚠️ 重要：闪电贷必须由[bold]合约[/bold]发起，不能直接 EOA 调用。")
    console.print("   先用 [cyan]generate[/cyan] 生成 receiver 模板，部署后才能 [cyan]call[/cyan]")


def cmd_generate(args, w3: Web3 = None):
    """生成 receiver 合约模板"""
    if args.provider == "aave":
        sol = AAVE_RECEIVER_TEMPLATE
    elif args.provider == "balancer":
        sol = BALANCER_RECEIVER_TEMPLATE
    elif args.provider == "both":
        sol = COMBO_RECEIVER_TEMPLATE
    else:
        console.print(f"[red]❌ 未知 provider: {args.provider}[/red]")
        sys.exit(1)

    out = args.output or f"./MyFlashLoan_{args.provider}.sol"
    with open(out, "w") as f:
        f.write(sol)
    console.print(f"[green]✅ 已生成 receiver 模板：[/green]{out}" if HAS_RICH
                  else f"✅ 已生成: {out}")
    console.print(f"\n下一步：")
    console.print(f"  1. 用 Foundry/Hardhat/Remix 编译并部署该合约")
    console.print(f"  2. 在合约的 _execute() 函数里写你的业务逻辑")
    console.print(f"  3. 用 [cyan]flashloan.py call --receiver 0xDeployed[/cyan] 调用")


def encode_aave_flashloan(receiver: str, assets: list, amounts: list,
                          modes: list, on_behalf: str,
                          params: bytes, referral: int = 0) -> bytes:
    """构造 Aave V3 flashLoan 的 calldata"""
    from eth_abi import encode

    # selector for flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)
    sig = "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)"
    selector = keccak(text=sig)[:4]
    args_encoded = encode(
        ["address", "address[]", "uint256[]", "uint256[]", "address", "bytes", "uint16"],
        [
            to_checksum_address(receiver),
            [to_checksum_address(a) for a in assets],
            amounts,
            modes,  # 0 = no debt（必须 0 才是真闪电贷）
            to_checksum_address(on_behalf),
            params,
            referral,
        ],
    )
    return selector + args_encoded


def encode_balancer_flashloan(recipient: str, tokens: list,
                              amounts: list, user_data: bytes) -> bytes:
    """构造 Balancer V2 flashLoan calldata"""
    from eth_abi import encode

    sig = "flashLoan(address,address[],uint256[],bytes)"
    selector = keccak(text=sig)[:4]
    args_encoded = encode(
        ["address", "address[]", "uint256[]", "bytes"],
        [
            to_checksum_address(recipient),
            [to_checksum_address(t) for t in tokens],
            amounts,
            user_data,
        ],
    )
    return selector + args_encoded


def parse_amount_list(raw: str, w3: Web3) -> list:
    """解析 '1000 ether,0.5 eth,1e18' 这种逗号分隔的金额"""
    parts = [p.strip() for p in raw.split(",")]
    return [parse_value("uint256", p, w3) for p in parts]


def cmd_encode(args, w3: Web3, native_symbol: str = "ETH"):
    """只生成 calldata，不发送"""
    assets = [a.strip() for a in (args.tokens or args.asset).split(",") if a.strip()]
    if args.amounts:
        amounts = parse_amount_list(args.amounts, w3)
    elif args.amount:
        amounts = [parse_value("uint256", args.amount, w3)] * len(assets)
    else:
        console.print("[red]❌ 必须指定 --amount 或 --amounts[/red]" if HAS_RICH
                      else "❌ 缺少金额")
        sys.exit(1)

    user_data = bytes.fromhex(args.params.removeprefix("0x")) if args.params else b""

    if args.provider == "aave":
        modes = [0] * len(assets)
        on_behalf = args.on_behalf or args.receiver
        calldata = encode_aave_flashloan(
            args.receiver, assets, amounts, modes, on_behalf, user_data, 0,
        )
        target = AAVE_V3_POOL.get((args.chain or "arb").lower())
    else:
        calldata = encode_balancer_flashloan(args.receiver, assets, amounts, user_data)
        target = BALANCER_V2_VAULT

    console.print(f"\n📦 Provider: [bold]{args.provider}[/bold]")
    console.print(f"   目标 (Pool/Vault): [cyan]{target}[/cyan]")
    console.print(f"   Receiver:  [cyan]{args.receiver}[/cyan]")
    console.print(f"   Assets:    {assets}")
    console.print(f"   Amounts:   {amounts}")
    console.print(f"   UserData:  0x{user_data.hex()}")
    console.print(f"\n[green]✅ Calldata:[/green]" if HAS_RICH else "\n✅ Calldata:")
    console.print(f"   0x{calldata.hex()}")
    console.print(f"\n💡 把这个 calldata 直接发给 [cyan]{target}[/cyan] 即可触发闪电贷")


def cmd_call(args, w3: Web3, native_symbol: str = "ETH"):
    """真实发送闪电贷"""
    account = load_account(args)
    if not account:
        console.print("[red]❌ 需要私钥[/red]" if HAS_RICH else "❌ 需要私钥")
        sys.exit(1)

    chain = args.chain or "arb"
    assets = [a.strip() for a in (args.tokens or args.asset).split(",") if a.strip()]
    if args.amounts:
        amounts = parse_amount_list(args.amounts, w3)
    elif args.amount:
        amounts = [parse_value("uint256", args.amount, w3)] * len(assets)
    else:
        console.print("[red]❌ 缺少金额[/red]"); sys.exit(1)

    user_data = bytes.fromhex(args.params.removeprefix("0x")) if args.params else b""

    if args.provider == "aave":
        modes = [0] * len(assets)
        on_behalf = args.on_behalf or args.receiver
        calldata = encode_aave_flashloan(
            args.receiver, assets, amounts, modes, on_behalf, user_data, 0,
        )
        target = AAVE_V3_POOL.get(chain.lower())
        if not target:
            console.print(f"[red]❌ 该链 ({chain}) 未配置 Aave V3 Pool[/red]")
            sys.exit(1)
        # 估算手续费
        for asset, amt in zip(assets, amounts):
            fee = amt * AAVE_FLASHLOAN_PREMIUM_BPS // 10000
            console.print(f"   💰 {asset} amount={amt}, fee={fee} (0.05%)")
    else:
        calldata = encode_balancer_flashloan(args.receiver, assets, amounts, user_data)
        target = BALANCER_V2_VAULT
        console.print("   💰 Balancer 手续费: 0")

    tx = build_tx(w3, account, target, calldata,
                  gas_limit=int(args.gas_limit) if args.gas_limit else 1_500_000)
    print_tx_summary(w3, tx, native_symbol=native_symbol,
                     signature=f"flashLoan via {args.provider}")

    # 模拟兜底
    console.print("\n🔬 模拟交易...")
    try:
        static_call(w3, target, calldata, sender=account.address)
        console.print("[green]✅ 模拟成功[/green]" if HAS_RICH else "✅ 模拟成功")
    except Exception as e:
        msg = str(e)[:300]
        console.print(f"[red]❌ 模拟失败：{msg}[/red]" if HAS_RICH else f"❌ {msg}")
        console.print("\n💡 常见原因：")
        console.print("   • Receiver 合约没正确实现 callback")
        console.print("   • Receiver 没有还币 + 手续费的逻辑")
        console.print("   • 池子里资产不够")
        if not args.force:
            sys.exit(1)

    if args.simulate:
        console.print("\n[yellow]🛑 --simulate 模式，未发送[/yellow]" if HAS_RICH
                      else "\n🛑 --simulate")
        return
    if not args.yes and not confirm():
        return
    send_tx(w3, account, tx, wait=True)


# ============================================================================
# Solidity Receiver 模板
# ============================================================================
AAVE_RECEIVER_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPool {
    function flashLoan(
        address receiver,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice Aave V3 闪电贷 receiver 模板。部署后把 _execute() 里写自己的逻辑。
contract AaveFlashLoanReceiver {
    address public immutable pool;
    address public owner;

    constructor(address _pool) {
        pool = _pool;
        owner = msg.sender;
    }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    /// @notice 入口：触发一次闪电贷
    function trigger(
        address[] calldata assets,
        uint256[] calldata amounts,
        bytes calldata params
    ) external onlyOwner {
        uint256[] memory modes = new uint256[](assets.length);
        // modes 全 0 = 真闪电贷（必须当场还）
        IPool(pool).flashLoan(
            address(this), assets, amounts, modes, address(this), params, 0
        );
    }

    /// @notice Aave 在借出资金后会回调这个函数
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address /*initiator*/,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == pool, "only pool");

        // ============= 在这里写你的业务逻辑 =============
        _execute(assets, amounts, params);
        // =============================================

        // 还回去：approve(pool, amount + premium) 让 Aave 取走
        for (uint256 i = 0; i < assets.length; i++) {
            uint256 owed = amounts[i] + premiums[i];
            IERC20(assets[i]).approve(pool, owed);
        }
        return true;
    }

    /// @dev 写你的业务逻辑：套利/清算/还债/...
    function _execute(
        address[] calldata assets,
        uint256[] calldata amounts,
        bytes calldata params
    ) internal {
        // TODO: 在这里实现具体策略
        // 例：
        //   1. 用借来的 USDC 在 DEX-A 买 ETH
        //   2. 在 DEX-B 卖 ETH 换更多 USDC
        //   3. 把利润留下，原数还给 Aave
    }

    /// @notice 提走合约里的利润
    function withdraw(address token, uint256 amount, address to) external onlyOwner {
        if (token == address(0)) {
            payable(to).transfer(amount);
        } else {
            IERC20(token).transfer(to, amount);
        }
    }

    receive() external payable {}
}
'''

BALANCER_RECEIVER_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault {
    function flashLoan(
        address recipient,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external;
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice Balancer V2 闪电贷 receiver 模板（手续费 0%！）
contract BalancerFlashLoanRecipient {
    IVault public constant VAULT = IVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address public owner;

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function trigger(
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes calldata userData
    ) external onlyOwner {
        VAULT.flashLoan(address(this), tokens, amounts, userData);
    }

    /// @notice Balancer 借出资金后回调
    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,  // Balancer 上 fee 都是 0
        bytes memory userData
    ) external {
        require(msg.sender == address(VAULT), "only vault");

        // ============= 业务逻辑 =============
        _execute(tokens, amounts, userData);
        // ====================================

        // 还回去：直接 transfer 给 Vault
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 owed = amounts[i] + feeAmounts[i];
            IERC20(tokens[i]).transfer(address(VAULT), owed);
        }
    }

    function _execute(
        address[] memory /*tokens*/,
        uint256[] memory /*amounts*/,
        bytes memory /*userData*/
    ) internal {
        // TODO: 套利/清算/...
    }

    function withdraw(address token, uint256 amount, address to) external onlyOwner {
        if (token == address(0)) payable(to).transfer(amount);
        else IERC20(token).transfer(to, amount);
    }
    receive() external payable {}
}
'''

COMBO_RECEIVER_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 同时支持 Aave V3 和 Balancer V2 的双 receiver
// (省略 — 实际部署时建议分开两个合约)
'''


# ============================================================================
# CLI
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="闪电贷集成（Aave V3 / Balancer V2）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="显示池子地址和手续费")
    p_info.add_argument("--chain", default="arb")

    p_gen = sub.add_parser("generate", help="生成 receiver 合约模板")
    p_gen.add_argument("--provider", choices=["aave", "balancer", "both"], default="aave")
    p_gen.add_argument("--output", "-o", help="输出 .sol 文件路径")

    common = lambda p: (
        p.add_argument("--rpc"),
        p.add_argument("--chain"),
        p.add_argument("--key"),
        p.add_argument("--keystore"),
        p.add_argument("--provider", choices=["aave", "balancer"], required=True),
        p.add_argument("--receiver", required=True, help="你部署的 receiver 合约地址"),
        p.add_argument("--asset", help="单一 asset 地址（与 --tokens 二选一）"),
        p.add_argument("--tokens", help="多 asset，逗号分隔"),
        p.add_argument("--amount", help="单一金额"),
        p.add_argument("--amounts", help="多金额，逗号分隔"),
        p.add_argument("--params", default="0x", help="user data，0x 开头 hex"),
        p.add_argument("--on-behalf", help="Aave 用：onBehalfOf 地址（默认 receiver）"),
        p.add_argument("--gas-limit"),
    )

    p_enc = sub.add_parser("encode", help="只编 calldata，不发送")
    common(p_enc)

    p_call = sub.add_parser("call", help="真实发送闪电贷")
    common(p_call)
    p_call.add_argument("--simulate", action="store_true")
    p_call.add_argument("--force", action="store_true")
    p_call.add_argument("--yes", "-y", action="store_true")

    args = parser.parse_args()

    if args.cmd == "info":
        cmd_info(args)
        return
    if args.cmd == "generate":
        cmd_generate(args)
        return

    rpc, scanner, native_symbol, _ = resolve_rpc(
        getattr(args, "chain", None), getattr(args, "rpc", None)
    )
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        console.print(f"[red]❌ 无法连接 {rpc}[/red]")
        sys.exit(1)
    console.print(f"🌐 已连接 [cyan]{rpc}[/cyan]  Chain: {w3.eth.chain_id}"
                  if HAS_RICH else f"🌐 {rpc}")

    if args.cmd == "encode":
        cmd_encode(args, w3, native_symbol)
    elif args.cmd == "call":
        cmd_call(args, w3, native_symbol)


if __name__ == "__main__":
    main()
