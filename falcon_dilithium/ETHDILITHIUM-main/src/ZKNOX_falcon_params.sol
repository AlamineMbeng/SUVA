// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

uint256 constant FALCON_Q         = 12289;
uint256 constant FALCON_N         = 256;
uint256 constant FALCON_SIG_BOUND = 16468416;
uint256 constant FALCON_SALT_LEN  = 40;
uint256 constant FALCON_HEAD_LEN  = 1;
uint256 constant FALCON_THRESHOLD = 61445;   // 5 * 12289
uint256 constant FALCON_ENC_S_LEN = 315;     // sig_bytelen(356) - 1 - 40
