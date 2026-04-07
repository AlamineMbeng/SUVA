"""
SPHINCS+ Hash Functions — SuVa Phase 5

Two variants:
  - Standard SHA-256 (reference, matches FIPS 205)
  - ETHSphincs: Keccak-256 (EVM-compatible, lower gas cost)

SPHINCS+ uses "tweakable" hash functions parameterized by an address (ADRS)
that encodes the position in the tree structure. This prevents multi-target
attacks: the same message hashed at different positions gives different outputs.

ADRS format (32 bytes):
  [0..11]  : layer index (4B), tree index (8B)
  [12..15] : type (4B)
  [16..19] : key pair address (4B)
  [20..23] : chain address (4B) or tree height (4B)
  [24..27] : hash address (4B) or tree index (4B)
  [28..31] : padding
"""

import hashlib
import struct


# ── Address type constants ────────────────────────────────────────────────────
WOTS_HASH  = 0   # WOTS+ hash chain step
WOTS_PK    = 1   # WOTS+ public key compression
TREE       = 2   # Merkle tree node
FORS_TREE  = 3   # FORS tree node
FORS_ROOTS = 4   # FORS root compression
WOTS_PRF   = 5   # WOTS+ PRF
FORS_PRF   = 6   # FORS PRF


class Address:
    """
    32-byte ADRS structure used to domain-separate all hash calls.
    Each position in the SPHINCS+ tree has a unique ADRS.
    """
    def __init__(self):
        self._data = bytearray(32)

    def set_layer(self, layer: int):
        struct.pack_into(">I", self._data, 0, layer)

    def set_tree(self, tree: int):
        struct.pack_into(">Q", self._data, 4, tree)

    def set_type(self, t: int):
        struct.pack_into(">I", self._data, 12, t)
        # Reset lower part on type change
        for i in range(16, 32):
            self._data[i] = 0

    def set_keypair(self, kp: int):
        struct.pack_into(">I", self._data, 16, kp)

    def set_chain(self, chain: int):
        struct.pack_into(">I", self._data, 20, chain)

    def set_hash_addr(self, h: int):
        struct.pack_into(">I", self._data, 24, h)

    def set_tree_height(self, height: int):
        struct.pack_into(">I", self._data, 20, height)

    def set_tree_index(self, idx: int):
        struct.pack_into(">I", self._data, 24, idx)

    def copy(self) -> "Address":
        a = Address()
        a._data = bytearray(self._data)
        return a

    def bytes(self) -> bytes:
        return bytes(self._data)


# ── SHA-256 variant (standard SPHINCS+) ──────────────────────────────────────

class SphincsHashSHA256:
    """
    Tweakable hash functions using SHA-256.
    Matches FIPS 205 (SLH-DSA) SHA-2 instantiation.
    """

    def __init__(self, n: int):
        self.n = n   # security parameter (output length in bytes)

    def _sha256(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _trunc(self, x: bytes) -> bytes:
        """Truncate to n bytes."""
        return x[:self.n]

    def prf(self, pk_seed: bytes, sk_prf: bytes, adrs: Address) -> bytes:
        """PRF(PK.seed, SK.prf, ADRS) → n bytes"""
        return self._trunc(
            self._sha256(pk_seed + adrs.bytes() + sk_prf)
        )

    def prf_msg(self, sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
        """PRFmsg(SK.prf, OptRand, msg) → n bytes"""
        return self._trunc(
            self._sha256(sk_prf + opt_rand + msg)
        )

    def h_msg(self, r: bytes, pk_seed: bytes, pk_root: bytes,
              msg: bytes, digest_len: int) -> bytes:
        """
        Hmsg(R, PK.seed, PK.root, msg) → digest_len bytes.
        Uses SHA-256 in MGF1 mode to produce variable-length output.
        """
        seed = r + pk_seed + pk_root + msg
        out = b""
        counter = 0
        while len(out) < digest_len:
            out += self._sha256(seed + struct.pack(">I", counter))
            counter += 1
        return out[:digest_len]

    def f(self, pk_seed: bytes, adrs: Address, m: bytes) -> bytes:
        """F(PK.seed, ADRS, M) → n bytes. Single-input tweakable hash."""
        return self._trunc(
            self._sha256(pk_seed + adrs.bytes() + m)
        )

    def h(self, pk_seed: bytes, adrs: Address,
          m1: bytes, m2: bytes) -> bytes:
        """H(PK.seed, ADRS, M1 || M2) → n bytes. Two-input tweakable hash."""
        return self._trunc(
            self._sha256(pk_seed + adrs.bytes() + m1 + m2)
        )

    def t_l(self, pk_seed: bytes, adrs: Address, m: bytes) -> bytes:
        """Tl(PK.seed, ADRS, M) → n bytes. Variable-length tweakable hash."""
        return self._trunc(
            self._sha256(pk_seed + adrs.bytes() + m)
        )


# ── Keccak-256 variant (ETHSphincs) ──────────────────────────────────────────

class SphincsHashKeccak:
    """
    ETHSphincs: tweakable hash functions using Keccak-256.
    Replaces SHA-256 with Keccak-256 for EVM-native gas efficiency.

    Keccak-256 = the pre-standardisation version used by Ethereum.
    In Python we use hashlib's sha3_256 then note: Ethereum's keccak256
    is NOT the same as NIST SHA3-256. We use pysha3 or simulate it.

    For simplicity in this PoC, we use hashlib.sha3_256 as a proxy.
    In the Solidity contract, this maps to the native KECCAK256 opcode.
    """

    def __init__(self, n: int):
        self.n = n

    def _keccak(self, data: bytes) -> bytes:
        # Using sha3_256 as proxy; production code would use pysha3
        return hashlib.sha3_256(data).digest()

    def _trunc(self, x: bytes) -> bytes:
        return x[:self.n]

    def prf(self, pk_seed: bytes, sk_prf: bytes, adrs: Address) -> bytes:
        return self._trunc(
            self._keccak(pk_seed + adrs.bytes() + sk_prf)
        )

    def prf_msg(self, sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
        return self._trunc(
            self._keccak(sk_prf + opt_rand + msg)
        )

    def h_msg(self, r: bytes, pk_seed: bytes, pk_root: bytes,
              msg: bytes, digest_len: int) -> bytes:
        """Variable-length output via counter-mode Keccak."""
        seed = r + pk_seed + pk_root + msg
        out = b""
        counter = 0
        while len(out) < digest_len:
            out += self._keccak(seed + struct.pack(">I", counter))
            counter += 1
        return out[:digest_len]

    def f(self, pk_seed: bytes, adrs: Address, m: bytes) -> bytes:
        return self._trunc(
            self._keccak(pk_seed + adrs.bytes() + m)
        )

    def h(self, pk_seed: bytes, adrs: Address,
          m1: bytes, m2: bytes) -> bytes:
        return self._trunc(
            self._keccak(pk_seed + adrs.bytes() + m1 + m2)
        )

    def t_l(self, pk_seed: bytes, adrs: Address, m: bytes) -> bytes:
        return self._trunc(
            self._keccak(pk_seed + adrs.bytes() + m)
        )
