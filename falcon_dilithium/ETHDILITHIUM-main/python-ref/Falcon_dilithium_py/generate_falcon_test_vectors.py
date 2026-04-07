"""
generate_falcon_test_vectors.py
================================
Generates Solidity test vectors for ZKNOX_ethfalcon.sol.

Run from: d:/Projects/suva/falcon_dilithium/ETHDILITHIUM-main/python-ref/
    py -3 -m Falcon_dilithium_py.generate_falcon_test_vectors

Produces: ../test/ZKNOX_ethfalcon.t.sol
"""

import sys
import os

# Make falcon_ref importable
_REF_DIR = os.path.join(os.path.dirname(__file__), "Falcon_falcon", "falcon_ref")
if _REF_DIR not in sys.path:
    sys.path.insert(0, _REF_DIR)

from falcon_sign import deserialize_to_poly, HEAD_LEN, SALT_LEN
from encoding import decompress

from .Falcon_falcon.falcon_eth import ETHFalcon256
from .Falcon_falcon.falcon_params import FALCON_256


# ── Constants ────────────────────────────────────────────────────────────────
Q          = FALCON_256["q"]           # 12289
N          = FALCON_256["n"]           # 256
SIG_BOUND  = FALCON_256["sig_bound"]   # 16468416
ENC_S_LEN  = FALCON_256["sig_bytelen"] - HEAD_LEN - SALT_LEN  # 315
MSG        = b"SuVa Protocol Phase 2 ETHFalcon test vector"


def generate_vectors():
    """Produce a deterministic (but randomly generated) test vector."""
    print("[*] Generating ETHFalcon256 test vectors …")

    sk, vk = ETHFalcon256.keygen()
    sig    = ETHFalcon256.sign(sk, MSG)

    # ── Decode vk → h ────────────────────────────────────────────────────────
    h = deserialize_to_poly(vk, N)                      # list[int], unsigned 0..q-1

    # ── Decode signature ─────────────────────────────────────────────────────
    salt  = sig[HEAD_LEN : HEAD_LEN + SALT_LEN]         # bytes, 40 B
    enc_s = sig[HEAD_LEN + SALT_LEN :]
    s1_signed = decompress(enc_s, ENC_S_LEN, N)        # list[int], signed
    assert s1_signed is not False, "decompress failed"

    s1_uint = [c % Q for c in s1_signed]               # unsigned mod q (0..q-1)

    # ── Sanity check ─────────────────────────────────────────────────────────
    ok = ETHFalcon256.verify(vk, MSG, sig)
    assert ok, "ETHFalcon256 verify() returned False — bad test vector!"
    print(f"    verify(correct) = {ok}  OK")

    wrong_msg = MSG + b"\x00"
    ok_wrong  = ETHFalcon256.verify(vk, wrong_msg, sig)
    print(f"    verify(wrong)   = {ok_wrong}  (expected False)")

    # ── Format helpers ────────────────────────────────────────────────────────
    def fmt_array256(name: str, values: list) -> str:
        """Emit:  uint256[256] memory name;\n  name[0]=v; …"""
        lines = [f"        uint256[256] memory {name};"]
        for i, v in enumerate(values):
            lines.append(f"        {name}[{i}] = {v};")
        return "\n".join(lines)

    def fmt_bytes(name: str, data: bytes) -> str:
        """Emit:  bytes memory name = hex\"…\";"""
        return f'        bytes memory {name} = hex"{data.hex()}";'

    h_block  = fmt_array256("h",  h)
    s1_block = fmt_array256("s1", s1_uint)
    salt_block       = fmt_bytes("salt",      salt)
    msg_block        = fmt_bytes("msg",       MSG)
    wrong_msg_block  = fmt_bytes("wrong_msg", MSG + b"\x00")

    # ── Write Solidity test file ──────────────────────────────────────────────
    out_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "test", "ZKNOX_ethfalcon.t.sol"
    )
    out_path = os.path.normpath(out_path)

    solidity_content = f"""\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;
// Code obtained from `generate_falcon_test_vectors.py`

import {{Test, console}} from "forge-std/Test.sol";
import {{ZKNOX_ethfalcon}} from "../src/ZKNOX_ethfalcon.sol";

contract ETHFalconTest is Test {{
    ZKNOX_ethfalcon falcon_contract;

    function setUp() public {{
        falcon_contract = new ZKNOX_ethfalcon();
    }}

    // ── Test 1 : correct signature must verify ───────────────────────────────
    function testVerify() public {{
{h_block}

{s1_block}

{salt_block}
{msg_block}

        bool result = falcon_contract.verify(h, salt, s1, msg);
        assertTrue(result, "ETHFalcon: valid signature should verify");
    }}

    // ── Test 2 : wrong message must NOT verify ───────────────────────────────
    function testVerifyWrongMsg() public {{
{h_block}

{s1_block}

{salt_block}
{wrong_msg_block}

        bool result = falcon_contract.verify(h, salt, s1, wrong_msg);
        assertFalse(result, "ETHFalcon: wrong message should not verify");
    }}
}}
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(solidity_content)

    print(f"[+] Written: {out_path}")
    print(f"    h[:4]      = {h[:4]}")
    print(f"    s1_uint[:4]= {s1_uint[:4]}")
    print(f"    salt[:8]   = {salt[:8].hex()}")
    return out_path


if __name__ == "__main__":
    generate_vectors()
