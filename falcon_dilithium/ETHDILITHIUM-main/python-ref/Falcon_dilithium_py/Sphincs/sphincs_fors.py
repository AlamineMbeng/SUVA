"""
FORS (Forest of Random Subsets) — SuVa Phase 5
Based on FIPS 205, Section 8

FORS is the few-time signature used at the base of SPHINCS+.
It signs the message digest before the hypertree takes over.

Structure:
  - k independent Merkle trees, each with 2^a leaves
  - Each tree's leaf is PRF(SK.seed, ADRS) — a secret value
  - Signature reveals k leaves (one per tree) + their auth paths
  - Public key: the k tree roots compressed together
"""

from .sphincs_hash import Address, FORS_TREE, FORS_ROOTS, FORS_PRF


def _fors_sk(h_func, sk_seed: bytes, pk_seed: bytes,
             adrs: Address, tree_idx: int, leaf_idx: int) -> bytes:
    """Generate the secret key for a FORS leaf."""
    sk_adrs = adrs.copy()
    sk_adrs.set_type(FORS_PRF)
    sk_adrs.set_tree_height(tree_idx)
    sk_adrs.set_tree_index(leaf_idx)
    return h_func.prf(pk_seed, sk_seed, sk_adrs)


def _fors_leaf(h_func, sk: bytes, pk_seed: bytes,
               adrs: Address, tree_idx: int, leaf_idx: int) -> bytes:
    """Hash the secret key to produce the Merkle leaf."""
    leaf_adrs = adrs.copy()
    leaf_adrs.set_type(FORS_TREE)
    leaf_adrs.set_tree_height(tree_idx)
    leaf_adrs.set_tree_index(leaf_idx)
    return h_func.f(pk_seed, leaf_adrs, sk)


def _fors_tree_root_and_auth(h_func, sk_seed: bytes, pk_seed: bytes,
                              adrs: Address, tree_idx: int,
                              a: int, target_leaf: int) -> tuple[bytes, list[bytes]]:
    """
    Build one FORS tree (height a, 2^a leaves).
    Returns (root, auth_path) for target_leaf.
    """
    num_leaves = 1 << a

    # Generate all leaves
    leaves = []
    for i in range(num_leaves):
        sk = _fors_sk(h_func, sk_seed, pk_seed, adrs, tree_idx, i)
        leaf = _fors_leaf(h_func, sk, pk_seed, adrs, tree_idx, i)
        leaves.append(leaf)

    # Build Merkle tree
    auth_path = []
    current = leaves
    target = target_leaf

    for height in range(a):
        sibling_idx = target ^ 1
        auth_path.append(current[sibling_idx])

        # Compute next level
        next_level = []
        for i in range(0, len(current), 2):
            node_adrs = adrs.copy()
            node_adrs.set_type(FORS_TREE)
            node_adrs.set_tree_height(height + 1 + tree_idx * a)
            node_adrs.set_tree_index(i >> 1)
            node = h_func.h(pk_seed, node_adrs, current[i], current[i + 1])
            next_level.append(node)

        current = next_level
        target >>= 1

    return current[0], auth_path


class FORS:
    """
    FORS few-time signature scheme.
    """

    def __init__(self, params: dict, h_func):
        self.n     = params["n"]
        self.k     = params["k"]        # number of trees
        self.a     = params["log_t"]    # log2(leaves per tree)
        self.h     = h_func

    def _message_to_indices(self, msg: bytes) -> list[int]:
        """
        Extract k indices from the message digest.
        Each index selects one leaf in its corresponding tree.
        """
        indices = []
        bits = 0
        value = 0
        mask = (1 << self.a) - 1   # a-bit mask

        for byte in msg:
            value = (value << 8) | byte
            bits += 8
            while bits >= self.a and len(indices) < self.k:
                bits -= self.a
                indices.append((value >> bits) & mask)

        return indices[:self.k]

    def sign(self, msg: bytes, sk_seed: bytes, pk_seed: bytes,
             adrs: Address) -> bytes:
        """
        FORS sign.
        Returns: k * (sk + auth_path) concatenated.
        Each entry: n (secret key) + a * n (auth path)
        """
        indices = self._message_to_indices(msg)
        sig = b""

        for i in range(self.k):
            leaf_idx = indices[i]
            # Reveal the secret key
            sk = _fors_sk(self.h, sk_seed, pk_seed, adrs, i, leaf_idx)
            sig += sk
            # Authentication path
            _, auth_path = _fors_tree_root_and_auth(
                self.h, sk_seed, pk_seed, adrs, i, self.a, leaf_idx
            )
            sig += b"".join(auth_path)

        return sig

    def pk_from_sig(self, msg: bytes, sig: bytes,
                    pk_seed: bytes, adrs: Address) -> bytes:
        """
        Recompute the FORS public key from a signature.
        Used during verification.
        Returns: compressed FORS pk (n bytes).
        """
        indices = self._message_to_indices(msg)
        roots = []

        entry_size = self.n * (1 + self.a)   # sk + auth_path per tree

        for i in range(self.k):
            entry = sig[i * entry_size: (i + 1) * entry_size]
            sk    = entry[:self.n]
            auth_bytes = entry[self.n:]
            auth_path = [
                auth_bytes[j * self.n: (j + 1) * self.n]
                for j in range(self.a)
            ]

            leaf_idx = indices[i]

            # Compute leaf from sk
            leaf = _fors_leaf(self.h, sk, pk_seed, adrs, i, leaf_idx)

            # Walk up the auth path
            node = leaf
            target = leaf_idx
            for height, sibling in enumerate(auth_path):
                node_adrs = adrs.copy()
                node_adrs.set_type(FORS_TREE)
                node_adrs.set_tree_height(height + 1 + i * self.a)
                if (target >> height) & 1 == 0:
                    node_adrs.set_tree_index(target >> (height + 1))
                    node = self.h.h(pk_seed, node_adrs, node, sibling)
                else:
                    node_adrs.set_tree_index((target - 1) >> (height + 1))
                    node = self.h.h(pk_seed, node_adrs, sibling, node)

            roots.append(node)

        # Compress k roots into one pk
        compress_adrs = adrs.copy()
        compress_adrs.set_type(FORS_ROOTS)
        return self.h.t_l(pk_seed, compress_adrs, b"".join(roots))

    def gen_pk(self, sk_seed: bytes, pk_seed: bytes, adrs: Address) -> bytes:
        """Generate FORS public key (used in keygen)."""
        roots = []
        for i in range(self.k):
            root, _ = _fors_tree_root_and_auth(
                self.h, sk_seed, pk_seed, adrs, i, self.a, 0
            )
            # We only need the root, so rebuild it properly
            num_leaves = 1 << self.a
            leaves = []
            for j in range(num_leaves):
                sk = _fors_sk(self.h, sk_seed, pk_seed, adrs, i, j)
                leaf = _fors_leaf(self.h, sk, pk_seed, adrs, i, j)
                leaves.append(leaf)
            # Compute root
            current = leaves
            for height in range(self.a):
                next_level = []
                for idx in range(0, len(current), 2):
                    node_adrs = adrs.copy()
                    node_adrs.set_type(FORS_TREE)
                    node_adrs.set_tree_height(height + 1 + i * self.a)
                    node_adrs.set_tree_index(idx >> 1)
                    node = self.h.h(pk_seed, node_adrs,
                                    current[idx], current[idx + 1])
                    next_level.append(node)
                current = next_level
            roots.append(current[0])

        compress_adrs = adrs.copy()
        compress_adrs.set_type(FORS_ROOTS)
        return self.h.t_l(pk_seed, compress_adrs, b"".join(roots))
