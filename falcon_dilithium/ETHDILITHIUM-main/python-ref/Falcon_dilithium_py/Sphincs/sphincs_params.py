"""
SPHINCS+ Parameter Sets — SuVa Phase 5
Based on FIPS 205 (SLH-DSA) — NIST standard August 2024

Selected set: SPHINCS+-128s-sha2 (smallest signatures, SHA-256 based)
ETHSphincs: SHA-256 replaced by Keccak-256 for EVM compatibility.

Parameter meaning:
  n      : security parameter (bytes)
  h      : total Merkle tree height (hypertree)
  d      : number of XMSS layers in hypertree
  log_t  : log2 of number of FORS leaves per tree (= a in FIPS 205)
  k      : number of FORS trees
  w      : Winternitz parameter for WOTS+
  sig_bytes : total signature size
"""

# ── SPHINCS+-128s ────────────────────────────────────────────────────────────
# Smallest signatures among 128-bit security sets (7,856 bytes)
# Recommended for on-chain use (lowest calldata cost)
SPHINCS_128s = {
    "name"      : "SPHINCS+-128s",
    "n"         : 16,       # 16 bytes = 128-bit security
    "h"         : 63,       # hypertree total height
    "d"         : 7,        # XMSS layers
    "log_t"     : 12,       # FORS: t = 2^12 = 4096 leaves per tree
    "k"         : 14,       # 14 FORS trees
    "w"         : 16,       # WOTS+ Winternitz (w=16 → len1=32, len2=3)
    "sig_bytes" : 7_856,    # total signature size in bytes
    "pk_bytes"  : 32,       # public key: PK.seed (n) + PK.root (n)
    "sk_bytes"  : 64,       # secret key: SK.seed (n) + SK.prf (n) + PK.seed + PK.root
}

# ── SPHINCS+-128f ────────────────────────────────────────────────────────────
# Fast signing, larger signatures (17,088 bytes)
SPHINCS_128f = {
    "name"      : "SPHINCS+-128f",
    "n"         : 16,
    "h"         : 66,
    "d"         : 22,
    "log_t"     : 6,
    "k"         : 33,
    "w"         : 16,
    "sig_bytes" : 17_088,
    "pk_bytes"  : 32,
    "sk_bytes"  : 64,
}

# ── SPHINCS+-256s ────────────────────────────────────────────────────────────
# Maximum security (256-bit), large signatures (29,792 bytes)
SPHINCS_256s = {
    "name"      : "SPHINCS+-256s",
    "n"         : 32,
    "h"         : 64,
    "d"         : 8,
    "log_t"     : 14,
    "k"         : 22,
    "w"         : 16,
    "sig_bytes" : 29_792,
    "pk_bytes"  : 64,
    "sk_bytes"  : 128,
}


def wots_len(params: dict) -> tuple[int, int, int]:
    """
    Compute WOTS+ lengths (len, len1, len2) from params.
    len1 = ceil(8n / log2(w))
    len2 = floor(log2(len1 * (w-1)) / log2(w)) + 1
    len  = len1 + len2
    """
    import math
    n, w = params["n"], params["w"]
    log_w = int(math.log2(w))
    len1 = math.ceil(8 * n / log_w)
    len2 = math.floor(math.log2(len1 * (w - 1)) / log_w) + 1
    return len1 + len2, len1, len2


def print_params(params: dict) -> None:
    """Pretty-print parameter set with derived values."""
    len_total, len1, len2 = wots_len(params)
    print(f"=== {params['name']} ===")
    print(f"  n={params['n']}  h={params['h']}  d={params['d']}")
    print(f"  k={params['k']}  log_t={params['log_t']}  w={params['w']}")
    print(f"  WOTS+ lengths: len={len_total}  len1={len1}  len2={len2}")
    print(f"  Signature: {params['sig_bytes']} bytes")
    print(f"  Public key: {params['pk_bytes']} bytes")
    print(f"  Tree height per layer: {params['h'] // params['d']}")


if __name__ == "__main__":
    for p in [SPHINCS_128s, SPHINCS_128f, SPHINCS_256s]:
        print_params(p)
        print()
