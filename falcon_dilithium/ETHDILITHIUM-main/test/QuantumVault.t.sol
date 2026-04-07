// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {QuantumVault} from "../src/QuantumVault.sol";
import {qUSDT}        from "../src/qUSDT.sol";
import {MockERC20}    from "../src/MockERC20.sol";

// ── Mock Falcon verifier ──────────────────────────────────────────────────────
/**
 * @notice MockFalcon — always returns `shouldPass`.
 *         Used to test QuantumVault logic independently from crypto.
 */
contract MockFalcon {
    bool public shouldPass = true;

    function setShouldPass(bool v) external { shouldPass = v; }

    function verify(
        uint256[256] calldata,
        bytes        calldata,
        uint256[256] calldata,
        bytes        calldata
    ) external view returns (bool) {
        return shouldPass;
    }
}

// ── Helper: build a dummy h array ────────────────────────────────────────────
library TestHelpers {
    function dummyH(uint256 seed) internal pure returns (uint256[256] memory h) {
        for (uint256 i = 0; i < 256; i++) {
            h[i] = (seed + i * 7) % 12289;
        }
    }

    function dummySalt() internal pure returns (bytes memory) {
        bytes memory salt = new bytes(40);
        for (uint256 i = 0; i < 40; i++) {
            salt[i] = bytes1(uint8(i + 1));
        }
        return salt;
    }

    function dummyS1() internal pure returns (uint256[256] memory s1) {
        for (uint256 i = 0; i < 256; i++) {
            s1[i] = i % 12289;
        }
    }
}

// ── QuantumVaultTest ──────────────────────────────────────────────────────────
contract QuantumVaultTest is Test {
    QuantumVault vault;
    qUSDT        quantum_usdt;
    MockERC20    mock_usdt;
    MockFalcon   mock_falcon;

    address user      = address(0xBEEF);
    address recipient = address(0xCAFE);

    uint256 constant INITIAL_BALANCE = 10_000_000; // 10 USDT (6 dec)
    uint256 constant DEPOSIT_AMOUNT  =  1_000_000; //  1 USDT

    // ── Setup ─────────────────────────────────────────────────────────────────
    function setUp() public {
        mock_falcon  = new MockFalcon();
        mock_usdt    = new MockERC20();
        quantum_usdt = new qUSDT(address(0));
        vault        = new QuantumVault(
            address(mock_falcon),
            address(mock_usdt),
            address(quantum_usdt)
        );
        quantum_usdt.setVault(address(vault));

        // Fund user and approve vault
        mock_usdt.mint(user, INITIAL_BALANCE);
        vm.prank(user);
        mock_usdt.approve(address(vault), type(uint256).max);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────
    function _registerAndDeposit() internal {
        uint256[256] memory h = TestHelpers.dummyH(42);
        vm.prank(user);
        vault.registerKey(h);
        vm.prank(user);
        vault.deposit(DEPOSIT_AMOUNT);
    }

    // ── Test 1: registerKey ───────────────────────────────────────────────────
    function testRegisterKey() public {
        uint256[256] memory h = TestHelpers.dummyH(42);
        bytes32 expectedHash  = keccak256(abi.encodePacked(h));

        vm.expectEmit(true, false, false, true);
        emit QuantumVault.KeyRegistered(user, expectedHash);

        vm.prank(user);
        vault.registerKey(h);

        assertEq(vault.pkHash(user), expectedHash, "pkHash mismatch");
    }

    // ── Test 2: deposit ───────────────────────────────────────────────────────
    function testDeposit() public {
        uint256[256] memory h = TestHelpers.dummyH(42);
        vm.prank(user);
        vault.registerKey(h);

        vm.expectEmit(true, false, false, true);
        emit QuantumVault.Deposit(user, DEPOSIT_AMOUNT);

        vm.prank(user);
        vault.deposit(DEPOSIT_AMOUNT);

        assertEq(vault.deposits(user),               DEPOSIT_AMOUNT, "deposits mapping wrong");
        assertEq(quantum_usdt.balanceOf(user),        DEPOSIT_AMOUNT, "qUSDT balance wrong");
        assertEq(mock_usdt.balanceOf(address(vault)), DEPOSIT_AMOUNT, "vault USDT balance wrong");
        assertEq(mock_usdt.balanceOf(user), INITIAL_BALANCE - DEPOSIT_AMOUNT, "user USDT balance wrong");
    }

    // ── Test 3: depositRequiresKey ────────────────────────────────────────────
    function testDepositRequiresKey() public {
        vm.prank(user);
        vm.expectRevert(bytes("QuantumVault: no key registered"));
        vault.deposit(DEPOSIT_AMOUNT);
    }

    // ── Test 4: withdraw (full flow, MockFalcon passes) ───────────────────────
    function testWithdraw() public {
        _registerAndDeposit();

        uint256[256] memory h    = TestHelpers.dummyH(42);
        bytes memory        salt = TestHelpers.dummySalt();
        uint256[256] memory s1   = TestHelpers.dummyS1();

        uint256 balBefore = mock_usdt.balanceOf(recipient);

        vm.expectEmit(true, true, false, true);
        emit QuantumVault.Withdrawal(user, recipient, DEPOSIT_AMOUNT);

        vm.prank(user);
        vault.withdraw(h, salt, s1, DEPOSIT_AMOUNT, recipient);

        assertEq(mock_usdt.balanceOf(recipient),  balBefore + DEPOSIT_AMOUNT, "recipient did not receive USDT");
        assertEq(quantum_usdt.balanceOf(user),     0,                          "qUSDT not burned");
        assertEq(vault.deposits(user),             0,                          "deposits not decremented");
    }

    // ── Test 5: withdrawInvalidSig ────────────────────────────────────────────
    function testWithdrawInvalidSig() public {
        _registerAndDeposit();
        mock_falcon.setShouldPass(false);

        uint256[256] memory h    = TestHelpers.dummyH(42);
        bytes memory        salt = TestHelpers.dummySalt();
        uint256[256] memory s1   = TestHelpers.dummyS1();

        vm.prank(user);
        vm.expectRevert(bytes("QuantumVault: invalid signature"));
        vault.withdraw(h, salt, s1, DEPOSIT_AMOUNT, recipient);
    }

    // ── Test 6: withdrawInsufficientBalance ───────────────────────────────────
    function testWithdrawInsufficientBalance() public {
        _registerAndDeposit();

        uint256[256] memory h    = TestHelpers.dummyH(42);
        bytes memory        salt = TestHelpers.dummySalt();
        uint256[256] memory s1   = TestHelpers.dummyS1();

        vm.prank(user);
        vm.expectRevert(bytes("QuantumVault: insufficient balance"));
        vault.withdraw(h, salt, s1, DEPOSIT_AMOUNT + 1, recipient);
    }

    // ── Test 7: nonceIncrement ────────────────────────────────────────────────
    function testNonceIncrement() public {
        _registerAndDeposit();

        // Deposit a second time so user has enough for two withdrawals
        mock_usdt.mint(user, DEPOSIT_AMOUNT);
        vm.prank(user);
        vault.deposit(DEPOSIT_AMOUNT);

        uint256[256] memory h    = TestHelpers.dummyH(42);
        bytes memory        salt = TestHelpers.dummySalt();
        uint256[256] memory s1   = TestHelpers.dummyS1();

        assertEq(vault.nonces(user), 0, "initial nonce should be 0");

        vm.prank(user);
        vault.withdraw(h, salt, s1, DEPOSIT_AMOUNT, recipient);
        assertEq(vault.nonces(user), 1, "nonce should be 1 after first withdrawal");

        vm.prank(user);
        vault.withdraw(h, salt, s1, DEPOSIT_AMOUNT, recipient);
        assertEq(vault.nonces(user), 2, "nonce should be 2 after second withdrawal");
    }

    // ── Test 8: withdrawWrongKey ──────────────────────────────────────────────
    function testWithdrawWrongKey() public {
        _registerAndDeposit();

        // Different h (seed 99 instead of 42) => different keccak256 hash
        uint256[256] memory wrong_h = TestHelpers.dummyH(99);
        bytes memory        salt    = TestHelpers.dummySalt();
        uint256[256] memory s1      = TestHelpers.dummyS1();

        vm.prank(user);
        vm.expectRevert(bytes("QuantumVault: wrong public key"));
        vault.withdraw(wrong_h, salt, s1, DEPOSIT_AMOUNT, recipient);
    }

    // ── Test 9: withdrawMessage helper ───────────────────────────────────────
    function testWithdrawMessageEncoding() public {
        _registerAndDeposit();

        bytes memory onchain = vault.withdrawMessage(user, DEPOSIT_AMOUNT, recipient);
        bytes memory manual  = abi.encodePacked(
            "SuVa:withdraw:",
            block.chainid,
            address(vault),
            uint256(0),          // nonce = 0 after one deposit (no withdrawal yet)
            DEPOSIT_AMOUNT,
            recipient
        );
        assertEq(keccak256(onchain), keccak256(manual), "withdrawMessage encoding mismatch");
    }

    // ── Test 10: depositZeroReverts ───────────────────────────────────────────
    function testDepositZeroReverts() public {
        uint256[256] memory h = TestHelpers.dummyH(42);
        vm.prank(user);
        vault.registerKey(h);

        vm.prank(user);
        vm.expectRevert(bytes("QuantumVault: zero amount"));
        vault.deposit(0);
    }

    // ── Test 11: withdrawZeroReverts ──────────────────────────────────────────
    function testWithdrawZeroReverts() public {
        _registerAndDeposit();

        uint256[256] memory h    = TestHelpers.dummyH(42);
        bytes memory        salt = TestHelpers.dummySalt();
        uint256[256] memory s1   = TestHelpers.dummyS1();

        vm.prank(user);
        vm.expectRevert(bytes("QuantumVault: zero amount"));
        vault.withdraw(h, salt, s1, 0, recipient);
    }

    // ── Test 12: qUSDT setVault idempotency guard ─────────────────────────────
    function testQUSDTSetVaultOnlyOnce() public {
        // vault is already set in setUp
        vm.expectRevert(bytes("qUSDT: vault already set"));
        quantum_usdt.setVault(address(0xDEAD));
    }

    // ── Test 13: qUSDT onlyVault guard ───────────────────────────────────────
    function testQUSDTOnlyVaultMint() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(bytes("qUSDT: caller is not vault"));
        quantum_usdt.mint(user, 1);
    }

    function testQUSDTOnlyVaultBurn() public {
        _registerAndDeposit();
        vm.prank(address(0xDEAD));
        vm.expectRevert(bytes("qUSDT: caller is not vault"));
        quantum_usdt.burn(user, 1);
    }

    // ── Test 14: real Falcon verifier (TODO: embed real vectors) ─────────────
    // testRealFalcon() is in QuantumVaultReal.t.sol (auto-generated by
    // generate_vault_test_vectors.py).  Run:
    //   cd python-ref && python -m Falcon_dilithium_py.generate_vault_test_vectors
    // to produce test/QuantumVaultReal.t.sol with embedded test vectors.
}
