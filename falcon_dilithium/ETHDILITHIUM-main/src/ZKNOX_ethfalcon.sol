// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_params.sol";
import "./ZKNOX_falcon_poly.sol";

/**
 * @title ZKNOX_ethfalcon
 * @notice Ethereum-friendly Falcon-256 signature verification.
 *         Uses KeccakPRNG in place of SHAKE256 for HashToPoint,
 *         matching the Python ETHFalcon256 reference implementation.
 *
 *         Verification equation (same as Falcon standard):
 *           t  = HashToPoint(salt || msg)
 *           s0 = t - h*s1  (mod q, mod X^256+1)
 *           ||s0||^2 + ||s1||^2 <= SIG_BOUND
 *
 *         Input pre-decoded (same pattern as ZKNOX_ethdilithium):
 *           h   : 256 public key coefficients (unsigned, 0..q-1)
 *           salt: 40-byte signing salt from signature
 *           s1  : 256 decoded s1 coefficients (mod q, unsigned 0..q-1)
 *           msg : original message bytes
 */
contract ZKNOX_ethfalcon {

    // -----------------------------------------------------------------------
    // PUBLIC ENTRY POINT
    // -----------------------------------------------------------------------

    /**
     * @notice Verify an ETHFalcon-256 signature.
     * @param h    256 decoded public-key coefficients (unsigned, 0..q-1)
     * @param salt 40-byte nonce extracted from the signature header
     * @param s1   256 decoded s1 coefficients (mod q, unsigned 0..q-1)
     * @param msg  Original signed message
     * @return     true iff the signature is valid
     */
    function verify(
        uint256[256] calldata h,
        bytes        calldata salt,
        uint256[256] calldata s1,
        bytes        calldata msg
    ) external pure returns (bool) {
        require(salt.length == FALCON_SALT_LEN, "bad salt length");

        // Step 1 — HashToPoint
        uint256[256] memory t = _hashToPoint(salt, msg);

        // Step 2 — hs1 = h * s1 mod (q, X^256+1)
        uint256[256] memory h_mem;
        uint256[256] memory s1_mem;
        for (uint256 i = 0; i < 256; ) {
            h_mem[i]  = h[i];
            s1_mem[i] = s1[i];
            unchecked { i++; }
        }
        uint256[256] memory hs1 = poly_mul(h_mem, s1_mem);

        // Step 3 — s0 = t - hs1 mod q
        uint256[256] memory s0;
        for (uint256 i = 0; i < 256; ) {
            s0[i] = (t[i] + FALCON_Q - hs1[i]) % FALCON_Q;
            unchecked { i++; }
        }

        // Step 4 — norm check
        uint256 norm = norm_sq_signed(s0) + norm_sq_signed(s1_mem);
        return norm <= FALCON_SIG_BOUND;
    }

    // -----------------------------------------------------------------------
    // INTERNAL — HashToPoint (KeccakPRNG)
    // -----------------------------------------------------------------------

    /**
     * @dev Reproduce Python hash_to_point_keccak(salt, message, n=256, q=12289).
     *
     *      Algorithm:
     *        seed  = keccak256(salt || msg)
     *        loop:
     *          block = keccak256(seed || counter_BE64)
     *          for each pair of bytes (b0, b1) in block:
     *            elt = (b0 << 8) | b1   // BIG-ENDIAN
     *            if elt < 61445: t[filled] = elt % 12289; filled++
     *          counter++
     *        until filled == 256
     */
    function _hashToPoint(bytes calldata salt, bytes calldata msg)
        internal
        pure
        returns (uint256[256] memory t)
    {
        // Initial seed: keccak256(salt || msg)
        bytes32 seed = keccak256(abi.encodePacked(salt, msg));

        uint256 filled  = 0;
        uint64  counter = 0;

        while (filled < 256) {
            // Generate 32-byte block
            bytes32 block_ = keccak256(abi.encodePacked(seed, counter));

            // Process 16 pairs of bytes (32 bytes → 16 pairs)
            for (uint256 byteIdx = 0; byteIdx < 32 && filled < 256; byteIdx += 2) {
                uint256 b0 = uint8(block_[byteIdx]);
                uint256 b1 = uint8(block_[byteIdx + 1]);
                uint256 elt = (b0 << 8) | b1;       // BIG-ENDIAN 16-bit value
                if (elt < FALCON_THRESHOLD) {        // rejection sampling
                    t[filled] = elt % FALCON_Q;
                    unchecked { filled++; }
                }
            }
            unchecked { counter++; }
        }
    }
}
