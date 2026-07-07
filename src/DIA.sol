// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 定义 RootDispatch 合约的接口
interface IRootDispatch {
    function getSubContractAddress(string memory _name) external view returns (address);
}

// 定义自动转发接口
interface IAutoForwarder {
    function notifyReceived(address from, uint256 amount) external;
}

contract DIA {
    string public name;
    string public symbol;
    uint8 public decimals = 6;
    uint256 public totalSupply;
    address public owner;
    address public admin;
    address manager;
    address feeTo;
    address pair;
    /* ---- 滑点 ---- */
    uint256 public constant FEE_NUMERATOR = 5; // 5%
    uint256 public constant FEE_DENOMINATOR = 100;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // 新增白名单
    mapping(address => bool) public feeWhitelist;

    // 新增事件
    event FeeWhitelistUpdated(address indexed account, bool status);

    // 新增函数：设置白名单，仅限 factory 调用
    function setFeeWhitelistBatch(address[] calldata accounts, bool status) external onlyAuthorized {
        for (uint256 i = 0; i < accounts.length; i++) {
            feeWhitelist[accounts[i]] = status;
            emit FeeWhitelistUpdated(accounts[i], status);
        }
    }

    // 部署时指定代币名称、符号和初始供应量
    constructor(string memory _name, string memory _symbol, address _owner) {
        name = _name;
        symbol = _symbol;
        owner = _owner;
        admin = msg.sender;
        totalSupply = 0;
        manager = IRootDispatch(owner).getSubContractAddress("TREASURY");
        require(manager != address(0), "Invalid manager address");
    }

    // 转账函数
    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    // 授权函数
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // 授权转账函数
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(balanceOf[from] >= value, "Insufficient balance");
        require(allowance[from][msg.sender] >= value, "Allowance exceeded");
        uint256 fee = 0;
        if (to == pair && from != feeTo && !feeWhitelist[from]) {
            fee = value * FEE_NUMERATOR / FEE_DENOMINATOR;
        }
        balanceOf[from] -= value;
        balanceOf[to] += value - fee;
        allowance[from][msg.sender] -= value;

        // 自动通知目标合约（如果 fee > 0）
        if (fee > 0) {
            balanceOf[feeTo] += fee;
            // try-catch 尝试通知 AutoForwarder
            try IAutoForwarder(feeTo).notifyReceived(from, fee) {
                // 成功，不做额外处理
            } catch {
                // 调用失败，忽略错误
            }
        }

        emit Transfer(from, to, value);
        return true;
    }

    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

    // 私有铸造函数
    function _mint(address to, uint256 value) private {
        balanceOf[to] += value;
        totalSupply += value;
        emit Transfer(address(0), to, value);
    }

    // 增发代币
    function mint(address to, uint256 value) external onlyAuthorized {
        _mint(to, value);
    }

    // 设置滑点流向
    function setFeeTo(address _feeTo) external onlyAuthorized {
        feeTo = _feeTo;
    }

    // 设置关注交换池地址
    function setPair(address _pair) external onlyAuthorized {
        pair = _pair;
    }

    function quitManager() external onlyAuthorized {
        admin = address(0);
    }

    modifier onlyAuthorized() {
        manager = IRootDispatch(owner).getSubContractAddress("TREASURY");
        require(msg.sender == manager || msg.sender == admin, "Caller must be Manager");
        _;
    }
}
