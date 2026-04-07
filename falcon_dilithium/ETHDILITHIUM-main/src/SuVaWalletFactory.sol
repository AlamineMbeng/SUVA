// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./SuVaWallet.sol";

/**
 * @title SuVaWalletFactory
 * @notice Deploys SuVaWallet instances — one per user.
 *         ERC-4337 compatible: uses CREATE2 for deterministic addresses.
 *
 *         Usage:
 *           1. Call createWallet(entryPoint, falconVerifier, owner, salt)
 *           2. Get the deterministic address before deployment via getAddress()
 */
contract SuVaWalletFactory {

    event WalletCreated(address indexed wallet, address indexed owner);

    /**
     * @notice Deploy a new SuVaWallet for a given owner.
     * @param _entryPoint      ERC-4337 EntryPoint address
     * @param _falconVerifier  ZKNOX_ethfalcon address
     * @param _owner           ECDSA owner address
     * @param salt             Arbitrary salt for CREATE2
     */
    function createWallet(
        address _entryPoint,
        address _falconVerifier,
        address _owner,
        uint256 salt
    ) external returns (SuVaWallet wallet) {
        bytes32 create2salt = keccak256(abi.encodePacked(_owner, salt));
        wallet = new SuVaWallet{salt: create2salt}(
            _entryPoint,
            _falconVerifier,
            _owner
        );
        emit WalletCreated(address(wallet), _owner);
    }

    /**
     * @notice Compute the deterministic address of a wallet before deployment.
     */
    function getAddress(
        address _entryPoint,
        address _falconVerifier,
        address _owner,
        uint256 salt
    ) external view returns (address) {
        bytes32 create2salt = keccak256(abi.encodePacked(_owner, salt));
        bytes memory bytecode = abi.encodePacked(
            type(SuVaWallet).creationCode,
            abi.encode(_entryPoint, _falconVerifier, _owner)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), create2salt, keccak256(bytecode))
        );
        return address(uint160(uint256(hash)));
    }
}
