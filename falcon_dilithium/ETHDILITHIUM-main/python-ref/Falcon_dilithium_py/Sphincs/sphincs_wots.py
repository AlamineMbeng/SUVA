"""
WOTS+ (Winternitz One-Time Signature) — SuVa Phase 5
Based on FIPS 205, Section 5

WOTS+ is the one-time signature primitive used at the leaves of
every XMSS tree in SPHINCS+.

Key idea:
  - Secret key: len random n-byte strings [sk_0, ..., sk_{len-1}]
  - Public key: apply the hash chain w-1 times to each sk_i
  - Sign message m: convert m to base-w digits [b_0,...,b_{len-1}],
    apply chain (w-1-b_i) times to each sk_i
  - Verify: apply chain b_i more times, compare to pk

The Winternitz parameter w controls the trade-off:
  - Larger w → fewer chains → smaller signature + faster verify
  - w=16 is the SPHINCS+ standard choice
"""

from .sphincs_hash import SphincsHashSHA256, SphincsHashKeccak, Address, WOTS_HASH, WOTS_PK, WOTS_PRF
import math


def _base_w(x: bytes, w: int, out_len: int) -> list[int]:
    """
    Convert byte string x to base-w representation.
    Returns list of out_len integers in {0, ..., w-1}.

    Algorithm (FIPS 205, Algorithm 1):
      Consume bits of x in groups of log2(w) bits.
    """
    log_w = int(math.log2(w))
    total = 0
    bits = 0
    result = []
    for byte in x:
        total = (total << 8) | byte
        bits += 8
        while bits >= log_w and len(result) < out_len:
            bits -= log_w
            result.append((total >> bits) & (w - 1))
    while len(result) < out_len:
        result.append(0)
    return result[:out_len]


def _chain(h_func, x: bytes, i: int, s: int,
           pk_seed: bytes, adrs: Address) -> bytes:
    """
    Compute the s steps of the hash chain starting at position i.
    chain(x, i, s, PK.seed, ADRS) applies F s times to x.

    Used in both sign (partial chain) and verify (complete chain).
    """
    if s == 0:
        return x
    adrs_copy = adrs.copy()
    tmp = x
    for j in range(i, i + s):
        adrs_copy.set_hash_addr(j)
        tmp = h_func.f(pk_seed, adrs_copy, tmp)
    return tmp


class WOTSPlus:
    """
    WOTS+ one-time signature scheme.
    Instantiated with a hash function (SHA-256 or Keccak).
    """

    def __init__(self, params: dict, h_func):
        self.n     = params["n"]
        self.w     = params["w"]
        self.h     = h_func
        log_w = int(math.log2(self.w))
        self.len1  = math.ceil(8 * self.n / log_w)
        self.len2  = math.floor(math.log2(self.len1 * (self.w - 1)) / log_w) + 1
        self.length = self.len1 + self.len2

    def _sk_element(self, sk_seed: bytes, pk_seed: bytes,
                    adrs: Address, i: int) -> bytes:
        """Generate the i-th secret key element using PRF."""
        a = adrs.copy()
        a.set_type(WOTS_PRF)
        a.set_keypair(adrs._data[16] if len(adrs._data) > 16 else 0)
        a.set_chain(i)
        a.set_hash_addr(0)
        return self.h.prf(pk_seed, sk_seed, a)

    def gen_pk(self, sk_seed: bytes, pk_seed: bytes, adrs: Address) -> bytes:
        """
        Generate WOTS+ public key.
        Applies the full chain (w-1 steps) to each sk element,
        then compresses with T_len.
        """
        wots_pk_adrs = adrs.copy()
        wots_pk_adrs.set_type(WOTS_HASH)

        # Build all pk elements
        pk_elements = []
        for i in range(self.length):
            sk_i = self._sk_element(sk_seed, pk_seed, adrs, i)
            wots_pk_adrs.set_chain(i)
            wots_pk_adrs.set_hash_addr(0)
            pk_i = _chain(self.h, sk_i, 0, self.w - 1, pk_seed, wots_pk_adrs)
            pk_elements.append(pk_i)

        # Compress: T_len(PK.seed, ADRS, pk[0] || ... || pk[len-1])
        compress_adrs = adrs.copy()
        compress_adrs.set_type(WOTS_PK)
        return self.h.t_l(pk_seed, compress_adrs, b"".join(pk_elements))

    def sign(self, msg: bytes, sk_seed: bytes,
             pk_seed: bytes, adrs: Address) -> bytes:
        """
        Sign an n-byte message digest.
        Returns signature: len * n bytes.

        For each base-w digit b_i of msg, apply chain (w-1-b_i) times.
        The verifier can complete to the full chain.
        """
        # Convert message to base-w
        msg_base_w = _base_w(msg, self.w, self.len1)

        # Compute checksum
        csum = sum(self.w - 1 - b for b in msg_base_w)
        # Encode checksum in base w
        log_w = int(math.log2(self.w))
        csum_bytes = csum.to_bytes((self.len2 * log_w + 7) // 8, 'big')
        csum_base_w = _base_w(csum_bytes, self.w, self.len2)

        msg_full = msg_base_w + csum_base_w   # length = len1 + len2 = length

        sig_adrs = adrs.copy()
        sig_adrs.set_type(WOTS_HASH)

        sig = b""
        for i in range(self.length):
            sk_i = self._sk_element(sk_seed, pk_seed, adrs, i)
            sig_adrs.set_chain(i)
            sig_adrs.set_hash_addr(0)
            # Apply chain from 0 to (w-1-msg_full[i]) steps
            sig += _chain(self.h, sk_i, 0, self.w - 1 - msg_full[i],
                          pk_seed, sig_adrs)
        return sig

    def pk_from_sig(self, msg: bytes, sig: bytes,
                    pk_seed: bytes, adrs: Address) -> bytes:
        """
        Recover the WOTS+ public key from a signature and message.
        Used during verification to reconstruct the leaf.

        For each digit b_i, apply chain b_i more steps.
        """
        msg_base_w = _base_w(msg, self.w, self.len1)
        csum = sum(self.w - 1 - b for b in msg_base_w)
        log_w = int(math.log2(self.w))
        csum_bytes = csum.to_bytes((self.len2 * log_w + 7) // 8, 'big')
        csum_base_w = _base_w(csum_bytes, self.w, self.len2)
        msg_full = msg_base_w + csum_base_w

        ver_adrs = adrs.copy()
        ver_adrs.set_type(WOTS_HASH)

        pk_elements = []
        for i in range(self.length):
            sig_i = sig[i * self.n: (i + 1) * self.n]
            ver_adrs.set_chain(i)
            ver_adrs.set_hash_addr(0)
            # sign applied chain from 0 for (w-1-b) steps → covers F_0..F_{w-2-b}
            # so complete the chain: start at (w-1-b), apply b more steps → covers F_{w-1-b}..F_{w-2}
            pk_i = _chain(self.h, sig_i, self.w - 1 - msg_full[i],
                          msg_full[i], pk_seed, ver_adrs)
            pk_elements.append(pk_i)

        # Compress to get candidate pk
        compress_adrs = adrs.copy()
        compress_adrs.set_type(WOTS_PK)
        return self.h.t_l(pk_seed, compress_adrs, b"".join(pk_elements))
