"""
SPHINCS+ Core — KeyGen / Sign / Verify — SuVa Phase 5
Based on FIPS 205 (SLH-DSA), Sections 9-10

Full SPHINCS+ = FORS + HyperTree (d layers of XMSS trees)

Sign flow:
  1. Compute randomised message hash R = PRFmsg(SK.prf, OptRand, msg)
  2. Digest = Hmsg(R, PK.seed, PK.root, msg) → (md, idx_tree, idx_leaf)
  3. Sign md with FORS → fors_sig
  4. Sign FORS pk with HyperTree (d XMSS layers) → ht_sig
  5. Signature = R || fors_sig || ht_sig

Verify flow:
  1. Recover FORS pk from (md, fors_sig)
  2. Verify HyperTree signature: walk d layers, check root == PK.root
"""

import os
import struct

from .sphincs_params import SPHINCS_128s, wots_len
from .sphincs_hash import (SphincsHashSHA256, SphincsHashKeccak,
                            Address, WOTS_HASH, TREE, FORS_TREE)
from .sphincs_wots import WOTSPlus
from .sphincs_merkle import XMSSTree
from .sphincs_fors import FORS


class SPHINCSPlus:
    """
    Full SPHINCS+ implementation.
    Supports both SHA-256 (standard) and Keccak-256 (ETHSphincs) variants.
    """

    def __init__(self, params: dict = None, use_keccak: bool = False):
        self.params = params or SPHINCS_128s
        self.n   = self.params["n"]
        self.h   = self.params["h"]
        self.d   = self.params["d"]
        self.k   = self.params["k"]
        self.a   = self.params["log_t"]
        self.w   = self.params["w"]
        self.h_tree = self.h // self.d   # XMSS tree height per layer

        if use_keccak:
            self.hf = SphincsHashKeccak(self.n)
            self.variant = "ETHSphincs"
        else:
            self.hf = SphincsHashSHA256(self.n)
            self.variant = "SPHINCS+"

        self.wots = WOTSPlus(self.params, self.hf)
        self.xmss = XMSSTree(self.params, self.hf, self.wots)
        self.fors = FORS(self.params, self.hf)

    # ── Digest decomposition ──────────────────────────────────────────────────

    def _split_digest(self, digest: bytes) -> tuple[bytes, int, int]:
        """
        Split Hmsg output into (md, idx_tree, idx_leaf).
        md       : k * a bits → used by FORS
        idx_tree : (h - h/d) bits → which XMSS tree at layer 0
        idx_leaf : h/d bits → which leaf in that tree
        """
        import math
        # Bit lengths
        fors_bits  = self.k * self.a
        tree_bits  = self.h - self.h_tree
        leaf_bits  = self.h_tree

        total_bits = fors_bits + tree_bits + leaf_bits
        total_bytes = (total_bits + 7) // 8

        # Convert digest to big integer for bit extraction
        val = int.from_bytes(digest[:total_bytes], 'big')

        # Extract from MSB
        leaf_mask = (1 << leaf_bits) - 1
        tree_mask = (1 << tree_bits) - 1
        fors_mask = (1 << fors_bits) - 1

        idx_leaf  = val & leaf_mask
        val >>= leaf_bits
        idx_tree  = val & tree_mask
        val >>= tree_bits
        md_int    = val & fors_mask

        # Convert md back to bytes
        md_bytes = (fors_bits + 7) // 8
        md = md_int.to_bytes(md_bytes, 'big')

        return md, idx_tree, idx_leaf

    # ── KeyGen ────────────────────────────────────────────────────────────────

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generate (pk, sk).
        sk = SK.seed || SK.prf || PK.seed || PK.root  (4n bytes)
        pk = PK.seed || PK.root                       (2n bytes)
        """
        sk_seed = os.urandom(self.n)
        sk_prf  = os.urandom(self.n)
        pk_seed = os.urandom(self.n)

        # Compute the hypertree root (top-level XMSS tree root)
        adrs = Address()
        adrs.set_layer(self.d - 1)
        adrs.set_tree(0)
        pk_root, _ = self._xmss_root(sk_seed, pk_seed, adrs)

        pk = pk_seed + pk_root
        sk = sk_seed + sk_prf + pk_seed + pk_root
        return pk, sk

    def _xmss_root(self, sk_seed: bytes, pk_seed: bytes,
                   adrs: Address) -> tuple[bytes, list]:
        """Build XMSS tree and return (root, all_leaves)."""
        num_leaves = 1 << self.h_tree
        leaves = []
        for i in range(num_leaves):
            wots_adrs = adrs.copy()
            wots_adrs.set_type(WOTS_HASH)
            wots_adrs.set_keypair(i)
            leaf = self.wots.gen_pk(sk_seed, pk_seed, wots_adrs)
            leaves.append(leaf)

        # Build tree
        current = leaves
        for height in range(self.h_tree):
            tree_adrs = adrs.copy()
            tree_adrs.set_type(TREE)
            tree_adrs.set_tree_height(height + 1)
            next_level = []
            for i in range(0, len(current), 2):
                tree_adrs.set_tree_index(i >> 1)
                node = self.hf.h(pk_seed, tree_adrs,
                                 current[i], current[i + 1])
                next_level.append(node)
            current = next_level

        return current[0], leaves

    # ── Sign ──────────────────────────────────────────────────────────────────

    def sign(self, msg: bytes, sk: bytes) -> bytes:
        """
        Sign msg.
        Returns signature bytes of size sig_bytes.
        """
        sk_seed = sk[:self.n]
        sk_prf  = sk[self.n:2*self.n]
        pk_seed = sk[2*self.n:3*self.n]
        pk_root = sk[3*self.n:4*self.n]

        # Step 1: randomise
        opt_rand = pk_seed   # deterministic: use pk_seed as randomness
        r = self.hf.prf_msg(sk_prf, opt_rand, msg)

        # Step 2: digest
        digest_len = (self.k * self.a + self.h - self.h_tree + self.h_tree + 7) // 8 + self.n
        digest = self.hf.h_msg(r, pk_seed, pk_root, msg, digest_len)
        md, idx_tree, idx_leaf = self._split_digest(digest)

        # Step 3: FORS sign
        fors_adrs = Address()
        fors_adrs.set_layer(0)
        fors_adrs.set_tree(idx_tree)
        fors_adrs.set_keypair(idx_leaf)
        fors_sig = self.fors.sign(md, sk_seed, pk_seed, fors_adrs)

        # FORS pk (needed to feed into HyperTree)
        fors_pk = self.fors.pk_from_sig(md, fors_sig, pk_seed, fors_adrs)

        # Step 4: HyperTree sign
        ht_sig = b""
        msg_ht = fors_pk
        tree   = idx_tree
        leaf   = idx_leaf

        for layer in range(self.d):
            adrs = Address()
            adrs.set_layer(layer)
            adrs.set_tree(tree)
            wots_sig, auth_bytes = self.xmss.sign(
                msg_ht, sk_seed, pk_seed, adrs, leaf
            )
            ht_sig += wots_sig + auth_bytes

            # Root becomes next message
            msg_ht = self.xmss.root_from_sig(
                leaf, msg_ht, wots_sig,
                [auth_bytes[i*self.n:(i+1)*self.n] for i in range(self.h_tree)],
                pk_seed, adrs
            )
            # Move to next layer
            leaf = tree & ((1 << self.h_tree) - 1)
            tree >>= self.h_tree

        return r + fors_sig + ht_sig

    # ── Verify ────────────────────────────────────────────────────────────────

    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        """
        Verify signature.
        Returns True if valid, False otherwise.
        """
        try:
            pk_seed = pk[:self.n]
            pk_root = pk[self.n:2*self.n]

            r = sig[:self.n]
            rest = sig[self.n:]

            # Recompute digest
            digest_len = (self.k * self.a + self.h - self.h_tree + self.h_tree + 7) // 8 + self.n
            digest = self.hf.h_msg(r, pk_seed, pk_root, msg, digest_len)
            md, idx_tree, idx_leaf = self._split_digest(digest)

            # FORS sig size
            fors_entry = self.n * (1 + self.a)
            fors_sig_len = self.k * fors_entry
            fors_sig = rest[:fors_sig_len]
            ht_sig   = rest[fors_sig_len:]

            # Recover FORS pk
            fors_adrs = Address()
            fors_adrs.set_layer(0)
            fors_adrs.set_tree(idx_tree)
            fors_adrs.set_keypair(idx_leaf)
            fors_pk = self.fors.pk_from_sig(md, fors_sig, pk_seed, fors_adrs)

            # Verify HyperTree
            len_total, _, _ = wots_len(self.params)
            wots_sig_len = len_total * self.n
            auth_len     = self.h_tree * self.n
            layer_sig_len = wots_sig_len + auth_len

            msg_ht = fors_pk
            tree   = idx_tree
            leaf   = idx_leaf

            for layer in range(self.d):
                adrs = Address()
                adrs.set_layer(layer)
                adrs.set_tree(tree)

                layer_sig  = ht_sig[layer * layer_sig_len: (layer + 1) * layer_sig_len]
                wots_sig   = layer_sig[:wots_sig_len]
                auth_bytes = layer_sig[wots_sig_len:]
                auth_path  = [
                    auth_bytes[i*self.n:(i+1)*self.n]
                    for i in range(self.h_tree)
                ]

                root = self.xmss.root_from_sig(
                    leaf, msg_ht, wots_sig, auth_path, pk_seed, adrs
                )
                msg_ht = root
                leaf = tree & ((1 << self.h_tree) - 1)
                tree >>= self.h_tree

            return msg_ht == pk_root

        except Exception:
            return False


# ── Convenience instances ─────────────────────────────────────────────────────

# Standard SPHINCS+-128s (SHA-256)
SPHINCS128s = SPHINCSPlus(SPHINCS_128s, use_keccak=False)

# ETHSphincs-128s (Keccak-256, EVM-native)
ETHSphincs128s = SPHINCSPlus(SPHINCS_128s, use_keccak=True)
