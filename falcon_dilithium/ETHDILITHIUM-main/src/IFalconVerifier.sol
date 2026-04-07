// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IFalconVerifier {
    function verify(
        uint256[256] calldata h,
        bytes        calldata salt,
        uint256[256] calldata s1,
        bytes        calldata message
    ) external pure returns (bool);
}
