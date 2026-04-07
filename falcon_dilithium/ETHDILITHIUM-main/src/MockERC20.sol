// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title MockERC20
 * @notice Minimal ERC-20 for testing (MockUSDT).
 *         No OpenZeppelin dependencies.
 *         name="Mock USDT", symbol="USDT", decimals=6
 *         mint() is public — for test use only.
 */
contract MockERC20 {
    string  public constant name     = "Mock USDT";
    string  public constant symbol   = "USDT";
    uint8   public constant decimals = 6;

    uint256 public totalSupply;

    mapping(address => uint256)                     public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ── Events ───────────────────────────────────────────────────────────────
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ── ERC-20 ────────────────────────────────────────────────────────────────
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "MockERC20: insufficient allowance");
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

    // ── Test helper ───────────────────────────────────────────────────────────
    /**
     * @notice Mint tokens. Public — for test use only.
     */
    function mint(address to, uint256 amount) external {
        totalSupply     += amount;
        balanceOf[to]   += amount;
        emit Transfer(address(0), to, amount);
    }

    // ── Internal ──────────────────────────────────────────────────────────────
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "MockERC20: from zero address");
        require(to   != address(0), "MockERC20: to zero address");
        require(balanceOf[from] >= amount, "MockERC20: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to]   += amount;
        emit Transfer(from, to, amount);
    }
}
