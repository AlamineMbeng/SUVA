// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "../src/ZKNOX_ethfalcon.sol";
import "../src/qUSDT.sol";
import "../src/QuantumVault.sol";
import "../src/MockERC20.sol";
import "../src/SuVaWallet.sol";
import "../src/SuVaWalletFactory.sol";

contract DeploySuVa is Script {
    function run() external {
        vm.startBroadcast();

        // ── Phase 3 contracts ─────────────────────────────────────────────────

        // 1. Deploy Falcon verifier
        ZKNOX_ethfalcon falcon = new ZKNOX_ethfalcon();
        console.log("ZKNOX_ethfalcon deployed at:  ", address(falcon));

        // 2. Deploy mock USDT (no real USDT on Sepolia)
        MockERC20 usdt = new MockERC20();
        console.log("MockERC20 (USDT) deployed at: ", address(usdt));

        // 3. Deploy qUSDT receipt token
        qUSDT qusdtToken = new qUSDT(address(0));
        console.log("qUSDT deployed at:            ", address(qusdtToken));

        // 4. Deploy QuantumVault
        QuantumVault vault = new QuantumVault(
            address(falcon),
            address(usdt),
            address(qusdtToken)
        );
        console.log("QuantumVault deployed at:     ", address(vault));

        // 5. Link qUSDT to vault
        qusdtToken.setVault(address(vault));
        console.log("qUSDT linked to vault.");

        // ── Phase 4 contracts ─────────────────────────────────────────────────

        // 6. Deploy SuVaWalletFactory
        SuVaWalletFactory walletFactory = new SuVaWalletFactory();
        console.log("SuVaWalletFactory deployed at:", address(walletFactory));

        // 7. Deploy one SuVaWallet for the deployer
        // ERC-4337 EntryPoint v0.6 on Sepolia
        address entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
        address deployer   = msg.sender;

        SuVaWallet wallet = walletFactory.createWallet(
            entryPoint,
            address(falcon),
            deployer,
            0
        );
        console.log("SuVaWallet deployed at:       ", address(wallet));

        vm.stopBroadcast();

        console.log("=== SuVa Full Deployment Complete ===");
        console.log("Network: Sepolia");
        console.log("--- Phase 3 ---");
        console.log("ZKNOX_ethfalcon: ", address(falcon));
        console.log("MockUSDT:        ", address(usdt));
        console.log("qUSDT:           ", address(qusdtToken));
        console.log("QuantumVault:    ", address(vault));
        console.log("--- Phase 4 ---");
        console.log("SuVaWalletFactory:", address(walletFactory));
        console.log("SuVaWallet:       ", address(wallet));
        console.log("EntryPoint:       ", entryPoint);
        console.log("Owner:            ", deployer);
    }
}
