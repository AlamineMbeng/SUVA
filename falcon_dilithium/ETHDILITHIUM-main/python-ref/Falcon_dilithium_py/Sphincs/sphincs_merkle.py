"""
Merkle Tree operations for SPHINCS+ — SuVa Phase 5
Based on FIPS 205, Section 6 (XMSS) and Section 7 (HyperTree)

A Merkle tree of height h has 2^h leaves.
Each internal node is H(left_child || right_child).
The root authenticates all leaves.

Authentication path: the h sibling nodes needed to recompute the root.
"""

from .sphincs_hash import Address, TREE, WOTS_HASH
from .sphincs_wots import WOTSPlus


def _compute_root(h_func, leaf: bytes, leaf_idx: int,
                  auth_path: list[bytes], pk_seed: bytes,
                  adrs: Address) -> bytes:
    """
    Compute the Merkle root from a leaf and its authentication path.
    auth_path[i] is the sibling at height i.

    At each level:
      - If leaf_idx is even: node = H(node, sibling)
      - If leaf_idx is odd:  node = H(sibling, node)
    Then move up: leaf_idx >>= 1
    """
    node = leaf
    tree_adrs = adrs.copy()
    tree_adrs.set_type(TREE)

    for height, sibling in enumerate(auth_path):
        tree_adrs.set_tree_height(height + 1)
        if (leaf_idx >> height) & 1 == 0:
            # Current node is left child
            tree_adrs.set_tree_index(leaf_idx >> (height + 1))
            node = h_func.h(pk_seed, tree_adrs, node, sibling)
        else:
            # Current node is right child
            tree_adrs.set_tree_index((leaf_idx - 1) >> (height + 1))
            node = h_func.h(pk_seed, tree_adrs, sibling, node)
    return node


class XMSSTree:
    """
    XMSS tree: one layer of the SPHINCS+ hypertree.
    Height = h // d per tree.

    Signs using WOTS+ at the leaves, authenticated by a Merkle tree.
    """

    def __init__(self, params: dict, h_func, wots: WOTSPlus):
        self.n      = params["n"]
        self.h_tree = params["h"] // params["d"]   # height of one XMSS tree
        self.h_func = h_func
        self.wots   = wots

    def _leaf_wots_pk(self, sk_seed: bytes, pk_seed: bytes,
                      adrs: Address, leaf_idx: int) -> bytes:
        """Compute the WOTS+ public key for leaf leaf_idx."""
        wots_adrs = adrs.copy()
        wots_adrs.set_type(WOTS_HASH)
        wots_adrs.set_keypair(leaf_idx)
        return self.wots.gen_pk(sk_seed, pk_seed, wots_adrs)

    def _build_auth_path(self, sk_seed: bytes, pk_seed: bytes,
                         adrs: Address, leaf_idx: int) -> tuple[bytes, list[bytes]]:
        """
        Build the Merkle tree and extract:
          - root: the tree root
          - auth_path: h_tree sibling nodes for leaf_idx
        """
        num_leaves = 1 << self.h_tree

        # Compute all leaves
        leaves = [
            self._leaf_wots_pk(sk_seed, pk_seed, adrs, i)
            for i in range(num_leaves)
        ]

        # Build tree level by level; store sibling of target path
        auth_path = []
        current_level = leaves
        target = leaf_idx

        for height in range(self.h_tree):
            # Sibling of target at this height
            sibling_idx = target ^ 1   # flip last bit
            auth_path.append(current_level[sibling_idx])

            # Compute next level
            tree_adrs = adrs.copy()
            tree_adrs.set_type(TREE)
            tree_adrs.set_tree_height(height + 1)

            next_level = []
            for i in range(0, len(current_level), 2):
                tree_adrs.set_tree_index(i >> 1)
                node = self.h_func.h(pk_seed, tree_adrs,
                                     current_level[i], current_level[i + 1])
                next_level.append(node)

            current_level = next_level
            target >>= 1

        root = current_level[0]
        return root, auth_path

    def sign(self, msg_hash: bytes, sk_seed: bytes, pk_seed: bytes,
             adrs: Address, leaf_idx: int) -> tuple[bytes, bytes]:
        """
        Sign msg_hash with leaf leaf_idx.
        Returns (wots_sig, auth_path_bytes).
        """
        # WOTS+ sign
        wots_adrs = adrs.copy()
        wots_adrs.set_type(WOTS_HASH)
        wots_adrs.set_keypair(leaf_idx)
        wots_sig = self.wots.sign(msg_hash, sk_seed, pk_seed, wots_adrs)

        # Authentication path
        _, auth_path = self._build_auth_path(sk_seed, pk_seed, adrs, leaf_idx)
        auth_bytes = b"".join(auth_path)

        return wots_sig, auth_bytes

    def root_from_sig(self, leaf_idx: int, msg_hash: bytes,
                      wots_sig: bytes, auth_path: list[bytes],
                      pk_seed: bytes, adrs: Address) -> bytes:
        """
        Verify: recompute tree root from WOTS+ signature and auth path.
        """
        # Recover WOTS+ pk from signature
        wots_adrs = adrs.copy()
        wots_adrs.set_type(WOTS_HASH)
        wots_adrs.set_keypair(leaf_idx)
        wots_pk = self.wots.pk_from_sig(msg_hash, wots_sig, pk_seed, wots_adrs)

        # Compute root
        return _compute_root(self.h_func, wots_pk, leaf_idx,
                             auth_path, pk_seed, adrs)
