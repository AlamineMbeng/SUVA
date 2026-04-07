// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./qUSDT.sol";
import "./IFalconVerifier.sol";

// NOTE: No recovery mechanism for lost Falcon keys. Funds are permanently locked
//       if the private key is lost.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/**
 * @title QuantumVault
 * @notice Quantum-secure USDT vault.
 *
 *         Architecture:
 *           - User registers Falcon-256 public key (stored as keccak256 hash on-chain,
 *             full key passed as calldata)
 *           - User deposits USDT → receives qUSDT 1:1
 *           - User withdraws: must provide valid ETHFalcon signature over a structured message
 *             Signature covers:
 *               "SuVa:withdraw:" || chainId(32B) || vault(20B) || nonce(32B) || amount(32B) || to(20B)
 *           - Nonce prevents replay attacks
 *
 * @dev Uses IFalconVerifier interface so MockFalcon can be substituted in tests.
 */
contract QuantumVault {
    // ── State ────────────────────────────────────────────────────────────────
    IFalconVerifier public immutable verifier;
    IERC20          public immutable usdt;
    qUSDT           public immutable qusdt;

    /// @notice pk hash: keccak256(abi.encodePacked(h)) where h is uint256[256]
    mapping(address => bytes32) public pkHash;
    /// @notice Amount of USDT deposited per user
    mapping(address => uint256) public deposits;
    /// @notice Replay-protection nonce per user (incremented on each withdrawal)
    mapping(address => uint256) public nonces;

    // ── Events ───────────────────────────────────────────────────────────────
    event KeyRegistered(address indexed user, bytes32 pkHash);
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, address indexed to, uint256 amount);

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _verifier, address _usdt, address _qusdt) {
        verifier = IFalconVerifier(_verifier);
        usdt     = IERC20(_usdt);
        qusdt    = qUSDT(_qusdt);
    }

    // ── Key registration ─────────────────────────────────────────────────────
    /**
     * @notice Register or update your Falcon-256 public key.
     * @param h 256 decoded Falcon public key coefficients (0..q-1 each)
     * WARNING: If you lose your Falcon private key, your funds are locked permanently.
     *          There is no recovery mechanism.
     */
    function registerKey(uint256[256] calldata h) external {
        bytes32 hash = keccak256(abi.encodePacked(h));
        pkHash[msg.sender] = hash;
        emit KeyRegistered(msg.sender, hash);
    }

    // ── Deposit ───────────────────────────────────────────────────────────────
    /**
     * @notice Deposit USDT. You must have a registered Falcon key first.
     * @param amount Amount of USDT to deposit (6 decimals)
     */
    function deposit(uint256 amount) external {
        require(pkHash[msg.sender] != bytes32(0), "QuantumVault: no key registered");
        require(amount > 0, "QuantumVault: zero amount");
        bool ok = usdt.transferFrom(msg.sender, address(this), amount);
        require(ok, "QuantumVault: USDT transfer failed");
        deposits[msg.sender] += amount;
        qusdt.mint(msg.sender, amount);
        emit Deposit(msg.sender, amount);
    }

    // ── Withdrawal ────────────────────────────────────────────────────────────
    /**
     * @notice Withdraw USDT. Requires a valid ETHFalcon signature.
     * @param h      256 Falcon public key coefficients (must match registered hash)
     * @param salt   40-byte salt from signature
     * @param s1     256 decoded s1 signature coefficients
     * @param amount Amount to withdraw
     * @param to     Recipient address
     */
    function withdraw(
        uint256[256] calldata h,
        bytes        calldata salt,
        uint256[256] calldata s1,
        uint256               amount,
        address               to
    ) external {
        // 1. Check key matches registered hash
        require(
            pkHash[msg.sender] == keccak256(abi.encodePacked(h)),
            "QuantumVault: wrong public key"
        );
        // 2. Check sufficient balance and non-zero amount
        require(amount > 0, "QuantumVault: zero amount");
        require(deposits[msg.sender] >= amount, "QuantumVault: insufficient balance");

        // 3. Build the signed message (must match Python signing code exactly)
        //    message = "SuVa:withdraw:" || chainId(32B) || vault(20B) || nonce(32B) || amount(32B) || to(20B)
        bytes memory message = abi.encodePacked(
            "SuVa:withdraw:",
            block.chainid,
            address(this),
            nonces[msg.sender],
            amount,
            to
        );

        // 4. Verify Falcon signature
        require(verifier.verify(h, salt, s1, message), "QuantumVault: invalid signature");

        // 5. Effects (checks-effects-interactions)
        nonces[msg.sender]++;
        deposits[msg.sender] -= amount;

        // 6. Interactions
        qusdt.burn(msg.sender, amount);
        bool ok = usdt.transfer(to, amount);
        require(ok, "QuantumVault: USDT transfer failed");

        emit Withdrawal(msg.sender, to, amount);
    }

    // ── View helpers ──────────────────────────────────────────────────────────
    /**
     * @notice Build the withdrawal message for a given user/amount/to.
     *         Use this to know exactly what to sign off-chain.
     */
    function withdrawMessage(
        address user,
        uint256 amount,
        address to
    ) external view returns (bytes memory) {
        return abi.encodePacked(
            "SuVa:withdraw:",
            block.chainid,
            address(this),
            nonces[user],
            amount,
            to
        );
    }
}
