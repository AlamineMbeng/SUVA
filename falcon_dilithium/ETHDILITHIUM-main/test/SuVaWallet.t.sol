// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../src/SuVaWallet.sol";
import "../src/SuVaWalletFactory.sol";

// ── Mock contracts ────────────────────────────────────────────────────────────

/// @notice Mock EntryPoint — records calls, simulates ERC-4337 EntryPoint
contract MockEntryPoint {
    mapping(address => uint256) public nonces;

    function getNonce(address sender, uint192) external view returns (uint256) {
        return nonces[sender];
    }

    function simulateValidation(
        SuVaWallet wallet,
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        return wallet.validateUserOp(userOp, userOpHash, 0);
    }

    // Allow wallet to send ETH prefund to entrypoint
    receive() external payable {}
}

/// @notice Mock Falcon verifier — controllable return value
contract MockFalconVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool _pass) external { shouldPass = _pass; }

    function verify(
        uint256[256] calldata,
        bytes        calldata,
        uint256[256] calldata,
        bytes        calldata
    ) external view returns (bool) {
        return shouldPass;
    }
}

/// @notice Simple target contract for execute() tests
contract MockTarget {
    uint256 public value;
    function setValue(uint256 v) external { value = v; }
    receive() external payable {}
}

// ── Test suite ────────────────────────────────────────────────────────────────

contract SuVaWalletTest is Test {

    MockEntryPoint      entryPoint;
    MockFalconVerifier  falconVerifier;
    SuVaWallet          wallet;
    SuVaWalletFactory   factory;

    // Test ECDSA key pair (Foundry vm.sign compatible)
    uint256 constant OWNER_PRIVATE_KEY = 0xA11CE;
    address          owner;

    // Dummy Falcon key (256 zeros — MockFalcon ignores it)
    uint256[256] falconH;
    bytes        falconSalt;
    uint256[256] falconS1;

    function setUp() public {
        owner = vm.addr(OWNER_PRIVATE_KEY);

        entryPoint     = new MockEntryPoint();
        falconVerifier = new MockFalconVerifier();

        wallet = new SuVaWallet(
            address(entryPoint),
            address(falconVerifier),
            owner
        );

        factory = new SuVaWalletFactory();

        // Register a dummy Falcon key
        vm.prank(owner);
        wallet.registerFalconKey(falconH);

        // Fund wallet with ETH for gas prefunds
        vm.deal(address(wallet), 1 ether);

        // Dummy falcon sig fields
        falconSalt = new bytes(40);
    }

    // ── Helper: build a UserOperation ────────────────────────────────────────

    function _buildUserOp(bytes memory sig) internal view returns (UserOperation memory) {
        return UserOperation({
            sender:               address(wallet),
            nonce:                0,
            initCode:             "",
            callData:             "",
            callGasLimit:         100_000,
            verificationGasLimit: 500_000,
            preVerificationGas:   50_000,
            maxFeePerGas:         1 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData:     "",
            signature:            sig
        });
    }

    function _buildValidSig(bytes32 userOpHash) internal view returns (bytes memory) {
        // ECDSA signature (65 bytes)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PRIVATE_KEY, userOpHash);
        bytes memory ecdsaSig = abi.encodePacked(r, s, v);

        // Falcon signature payload
        bytes memory falconPayload = abi.encode(falconH, falconSalt, falconS1);

        return abi.encodePacked(ecdsaSig, falconPayload);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// @notice Wallet is deployed with correct owner and entryPoint
    function testDeployment() public view {
        assertEq(wallet.owner(), owner);
        assertEq(address(wallet.entryPoint()), address(entryPoint));
        assertEq(address(wallet.falconVerifier()), address(falconVerifier));
    }

    /// @notice Falcon key registration stores correct hash
    function testRegisterFalconKey() public {
        uint256[256] memory newH;
        newH[0] = 42;
        vm.prank(owner);
        wallet.registerFalconKey(newH);
        assertEq(wallet.falconPkHash(), keccak256(abi.encodePacked(newH)));
    }

    /// @notice Only owner can register a Falcon key
    function testRegisterFalconKeyOnlyOwner() public {
        uint256[256] memory newH;
        vm.prank(address(0xBEEF));
        vm.expectRevert("SuVaWallet: not authorized");
        wallet.registerFalconKey(newH);
    }

    /// @notice validateUserOp succeeds when both ECDSA and Falcon are valid
    function testValidateUserOpSuccess() public {
        bytes32 userOpHash = keccak256("test-userop-hash");
        bytes memory sig = _buildValidSig(userOpHash);
        UserOperation memory userOp = _buildUserOp(sig);

        vm.prank(address(entryPoint));
        uint256 result = wallet.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0); // SIG_VALIDATION_SUCCESS
    }

    /// @notice validateUserOp fails when ECDSA signature is wrong
    function testValidateUserOpWrongECDSA() public {
        bytes32 userOpHash = keccak256("test-userop-hash");

        // Sign with wrong key
        uint256 wrongKey = 0xBAD;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory ecdsaSig    = abi.encodePacked(r, s, v);
        bytes memory falconPayload = abi.encode(falconH, falconSalt, falconS1);
        bytes memory sig = abi.encodePacked(ecdsaSig, falconPayload);

        UserOperation memory userOp = _buildUserOp(sig);
        vm.prank(address(entryPoint));
        uint256 result = wallet.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1); // SIG_VALIDATION_FAILED
    }

    /// @notice validateUserOp fails when Falcon signature is invalid
    function testValidateUserOpWrongFalcon() public {
        falconVerifier.setShouldPass(false);

        bytes32 userOpHash = keccak256("test-userop-hash");
        bytes memory sig = _buildValidSig(userOpHash);
        UserOperation memory userOp = _buildUserOp(sig);

        vm.prank(address(entryPoint));
        uint256 result = wallet.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1); // SIG_VALIDATION_FAILED
    }

    /// @notice validateUserOp fails when signature is too short
    function testValidateUserOpShortSig() public {
        bytes32 userOpHash = keccak256("test-userop-hash");
        bytes memory sig = new bytes(10); // too short
        UserOperation memory userOp = _buildUserOp(sig);

        vm.prank(address(entryPoint));
        uint256 result = wallet.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1); // SIG_VALIDATION_FAILED
    }

    /// @notice validateUserOp fails when no Falcon key registered
    function testValidateUserOpNoFalconKey() public {
        // Deploy fresh wallet with no key registered
        SuVaWallet freshWallet = new SuVaWallet(
            address(entryPoint),
            address(falconVerifier),
            owner
        );
        vm.deal(address(freshWallet), 1 ether);

        bytes32 userOpHash = keccak256("test-userop-hash");
        bytes memory sig = _buildValidSig(userOpHash);
        UserOperation memory userOp = _buildUserOp(sig);
        userOp.sender = address(freshWallet);

        vm.prank(address(entryPoint));
        uint256 result = freshWallet.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1); // SIG_VALIDATION_FAILED — no key registered
    }

    /// @notice validateUserOp fails when called by non-EntryPoint
    function testValidateUserOpOnlyEntryPoint() public {
        bytes32 userOpHash = keccak256("test-userop-hash");
        bytes memory sig = _buildValidSig(userOpHash);
        UserOperation memory userOp = _buildUserOp(sig);

        vm.prank(address(0xBEEF));
        vm.expectRevert("SuVaWallet: not EntryPoint");
        wallet.validateUserOp(userOp, userOpHash, 0);
    }

    /// @notice execute() runs a call to a target contract
    function testExecute() public {
        MockTarget target = new MockTarget();

        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 42);
        vm.prank(address(entryPoint));
        wallet.execute(address(target), 0, data);

        assertEq(target.value(), 42);
    }

    /// @notice execute() only callable by EntryPoint
    function testExecuteOnlyEntryPoint() public {
        MockTarget target = new MockTarget();
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 42);

        vm.prank(address(0xBEEF));
        vm.expectRevert("SuVaWallet: not EntryPoint");
        wallet.execute(address(target), 0, data);
    }

    /// @notice execute() sends ETH correctly
    function testExecuteSendsETH() public {
        address recipient = address(0x1234);
        vm.prank(address(entryPoint));
        wallet.execute(recipient, 0.1 ether, "");
        assertEq(recipient.balance, 0.1 ether);
    }

    /// @notice Factory deploys wallet with correct owner
    function testFactoryCreateWallet() public {
        SuVaWallet newWallet = factory.createWallet(
            address(entryPoint),
            address(falconVerifier),
            owner,
            0
        );
        assertEq(newWallet.owner(), owner);
        assertEq(address(newWallet.entryPoint()), address(entryPoint));
    }

    /// @notice Factory getAddress matches actual deployed address
    function testFactoryGetAddress() public {
        address predicted = factory.getAddress(
            address(entryPoint),
            address(falconVerifier),
            owner,
            0
        );
        SuVaWallet deployed = factory.createWallet(
            address(entryPoint),
            address(falconVerifier),
            owner,
            0
        );
        assertEq(predicted, address(deployed));
    }

    /// @notice Wallet receives ETH
    function testReceiveETH() public {
        uint256 before = address(wallet).balance;
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(wallet).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(wallet).balance, before + 0.5 ether);
    }
}
