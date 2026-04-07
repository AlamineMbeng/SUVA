// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title SuVaWallet
 * @notice ERC-4337 smart contract wallet with dual-signature validation:
 *         ECDSA (standard Ethereum) + Falcon-256 (post-quantum).
 *
 *         A UserOperation is only valid if BOTH signatures are present and correct.
 *         This provides defense-in-depth: quantum computers cannot steal funds
 *         even if ECDSA is broken in the future.
 *
 *         Signature encoding (userOp.signature):
 *           [0..64]   ECDSA signature (65 bytes)
 *           [65..]    Falcon signature: abi.encode(h, salt, s1)
 *                     where h = uint256[256], salt = bytes, s1 = uint256[256]
 */

// ── ERC-4337 interfaces ───────────────────────────────────────────────────────

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes   initCode;
    bytes   callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes   paymasterAndData;
    bytes   signature;
}

interface IEntryPoint {
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
    function getNonce(address sender, uint192 key) external view returns (uint256);
}

interface IAccount {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32               userOpHash,
        uint256               missingAccountFunds
    ) external returns (uint256 validationData);
}

// ── Falcon verifier interface ─────────────────────────────────────────────────
import "./IFalconVerifier.sol";

// ── SuVaWallet ────────────────────────────────────────────────────────────────

contract SuVaWallet is IAccount {

    // ── Constants ─────────────────────────────────────────────────────────────
    uint256 constant SIG_VALIDATION_FAILED  = 1;
    uint256 constant SIG_VALIDATION_SUCCESS = 0;

    // ── Immutables ────────────────────────────────────────────────────────────
    IEntryPoint     public immutable entryPoint;
    IFalconVerifier public immutable falconVerifier;

    // ── State ─────────────────────────────────────────────────────────────────

    /// @notice ECDSA owner address
    address public owner;

    /// @notice keccak256(abi.encodePacked(h)) — Falcon public key commitment
    bytes32 public falconPkHash;

    // ── Events ────────────────────────────────────────────────────────────────
    event FalconKeyRegistered(bytes32 pkHash);
    event Executed(address indexed target, uint256 value, bytes data);

    // ── Modifiers ─────────────────────────────────────────────────────────────
    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "SuVaWallet: not EntryPoint");
        _;
    }

    modifier onlyOwnerOrEntryPoint() {
        require(
            msg.sender == owner || msg.sender == address(entryPoint),
            "SuVaWallet: not authorized"
        );
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────
    constructor(
        address _entryPoint,
        address _falconVerifier,
        address _owner
    ) {
        entryPoint    = IEntryPoint(_entryPoint);
        falconVerifier = IFalconVerifier(_falconVerifier);
        owner         = _owner;
    }

    // ── Falcon key management ─────────────────────────────────────────────────

    /**
     * @notice Register or update the Falcon-256 public key.
     * @param h  256 Falcon public key coefficients
     */
    function registerFalconKey(uint256[256] calldata h) external onlyOwnerOrEntryPoint {
        falconPkHash = keccak256(abi.encodePacked(h));
        emit FalconKeyRegistered(falconPkHash);
    }

    // ── ERC-4337 core ─────────────────────────────────────────────────────────

    /**
     * @notice Validate a UserOperation. Called by EntryPoint before execution.
     *
     *         userOp.signature layout:
     *           bytes  0..64  : ECDSA signature (65 bytes, v/r/s)
     *           bytes 65..end : abi.encode(uint256[256] h, bytes salt, uint256[256] s1)
     *
     * @return validationData 0 = success, 1 = failure
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32               userOpHash,
        uint256               missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        // Pay EntryPoint if needed
        if (missingAccountFunds > 0) {
            (bool ok,) = payable(address(entryPoint)).call{value: missingAccountFunds}("");
            require(ok, "SuVaWallet: prefund failed");
        }

        // Split the composite signature
        if (userOp.signature.length < 65) return SIG_VALIDATION_FAILED;

        bytes memory ecdsaSig  = _slice(userOp.signature, 0, 65);
        bytes memory falconSig = _slice(userOp.signature, 65, userOp.signature.length - 65);

        // 1. Verify ECDSA
        if (!_verifyECDSA(userOpHash, ecdsaSig)) return SIG_VALIDATION_FAILED;

        // 2. Verify Falcon
        if (!_verifyFalcon(userOpHash, falconSig)) return SIG_VALIDATION_FAILED;

        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @notice Execute a call. Only callable by EntryPoint (after validateUserOp).
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint {
        (bool ok, bytes memory result) = target.call{value: value}(data);
        if (!ok) {
            assembly { revert(add(result, 32), mload(result)) }
        }
        emit Executed(target, value, data);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /**
     * @notice Verify ECDSA signature over userOpHash.
     *         Signer must be the registered owner.
     */
    function _verifyECDSA(
        bytes32 hash,
        bytes memory sig
    ) internal view returns (bool) {
        if (sig.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        address recovered = ecrecover(hash, v, r, s);
        return recovered != address(0) && recovered == owner;
    }

    /**
     * @notice Verify Falcon signature.
     *         falconSig = abi.encode(uint256[256] h, bytes salt, uint256[256] s1)
     *         The signed message is the userOpHash (32 bytes).
     */
    function _verifyFalcon(
        bytes32 userOpHash,
        bytes memory falconSig
    ) internal view returns (bool) {
        if (falconPkHash == bytes32(0)) return false;

        (uint256[256] memory h, bytes memory salt, uint256[256] memory s1) =
            abi.decode(falconSig, (uint256[256], bytes, uint256[256]));

        // Check the public key matches the registered hash
        if (keccak256(abi.encodePacked(h)) != falconPkHash) return false;

        // Message signed = the 32-byte userOpHash
        bytes memory message = abi.encodePacked(userOpHash);

        return falconVerifier.verify(h, salt, s1, message);
    }

    /**
     * @notice Slice a bytes array: return b[start..start+length]
     */
    function _slice(
        bytes memory b,
        uint256 start,
        uint256 length
    ) internal pure returns (bytes memory result) {
        result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = b[start + i];
        }
    }

    // ── ETH receive ───────────────────────────────────────────────────────────
    receive() external payable {}
}
