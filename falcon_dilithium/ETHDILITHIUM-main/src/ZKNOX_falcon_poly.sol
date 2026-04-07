// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_params.sol";

/**
 * @title ZKNOX_falcon_poly
 * @notice Polynomial operations in Z_12289[X]/(X^256+1) for Falcon-256.
 *         Rule: X^256 ≡ -1, so if i+j >= 256, the term subtracts instead of adds.
 */

/**
 * @notice Schoolbook polynomial multiplication in Z_q[X]/(X^256+1).
 *         O(n^2) — coefficients unsigned, result in [0, q-1].
 * @param a  First polynomial, 256 coefficients in [0, q-1]
 * @param b  Second polynomial, 256 coefficients in [0, q-1]
 * @return r Product polynomial, 256 coefficients in [0, q-1]
 */
function poly_mul(uint256[256] memory a, uint256[256] memory b)
    pure
    returns (uint256[256] memory r)
{
    for (uint256 i = 0; i < 256; ) {
        uint256 ai = a[i];
        if (ai == 0) {
            unchecked { i++; }
            continue;
        }
        for (uint256 j = 0; j < 256; ) {
            uint256 idx = (i + j) & 0xff; // % 256
            uint256 prod = (ai * b[j]) % FALCON_Q;
            if (i + j >= 256) {
                // X^256 ≡ -1 → subtract
                r[idx] = (r[idx] + FALCON_Q - prod) % FALCON_Q;
            } else {
                r[idx] = (r[idx] + prod) % FALCON_Q;
            }
            unchecked { j++; }
        }
        unchecked { i++; }
    }
}

/**
 * @notice Squared L2 norm with centered coefficients.
 *         If c > q/2, treat c as c - q (negative value).
 * @param s  Polynomial with coefficients in [0, q-1]
 * @return norm_sq  Sum of squared centered coefficients
 */
function norm_sq_signed(uint256[256] memory s)
    pure
    returns (uint256 norm_sq)
{
    uint256 half_q = FALCON_Q >> 1; // 6144
    for (uint256 i = 0; i < 256; ) {
        uint256 c = s[i];
        int256 centered;
        if (c > half_q) {
            centered = int256(c) - int256(FALCON_Q);
        } else {
            centered = int256(c);
        }
        norm_sq += uint256(centered * centered);
        unchecked { i++; }
    }
}
