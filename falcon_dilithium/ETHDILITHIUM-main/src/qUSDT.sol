// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title qUSDT
 * @notice Quantum USDT — ERC-20 token minted/burned exclusively by QuantumVault.
 *         name="Quantum USDT", symbol="qUSDT", decimals=6
 *
 *         Two-step initialization:
 *           1. Deploy qUSDT (vault = address(0))
 *           2. Deploy QuantumVault
 *           3. Call qUSDT.setVault(address(vault))  — callable only once
 */
contract qUSDT {
    string  public constant name     = "Quantum USDT";
    string  public constant symbol   = "qUSDT";
    uint8   public constant decimals = 6;

    uint256 public totalSupply;

    address public vault;

    mapping(address => uint256)                     public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ── Events ───────────────────────────────────────────────────────────────
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _vault) {
        vault = _vault;
    }

    // ── Vault bootstrap ───────────────────────────────────────────────────────
    /**
     * @notice Set vault address. Callable only once (when vault == address(0)).
     */
    function setVault(address _vault) external {
        require(vault == address(0), "qUSDT: vault already set");
        require(_vault != address(0), "qUSDT: zero address");
        vault = _vault;
    }

    // ── Modifiers ─────────────────────────────────────────────────────────────
    modifier onlyVault() {
        require(vault != address(0), "qUSDT: vault not set");
        require(msg.sender == vault, "qUSDT: caller is not vault");
        _;
    }

    // ── Vault-only operations ─────────────────────────────────────────────────
    function mint(address to, uint256 amount) external onlyVault {
        totalSupply   += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external onlyVault {
        require(balanceOf[from] >= amount, "qUSDT: burn amount exceeds balance");
        balanceOf[from] -= amount;
        totalSupply     -= amount;
        emit Transfer(from, address(0), amount);
    }

    // ── ERC-20 ────────────────────────────────────────────────────────────────
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "qUSDT: insufficient allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // ── Internal ──────────────────────────────────────────────────────────────
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "qUSDT: from zero address");
        require(to   != address(0), "qUSDT: to zero address");
        require(balanceOf[from] >= amount, "qUSDT: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to]   += amount;
        emit Transfer(from, to, amount);
    }
}
