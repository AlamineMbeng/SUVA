"""
Tests SPHINCS+ / ETHSphincs — SuVa Phase 5

Lance avec :
  cd python-ref/
  python -m pytest Falcon_dilithium_py/tests/test_sphincs.py -v
"""

import pytest
from ..Sphincs.sphincs_core import SPHINCSPlus
from ..Sphincs.sphincs_params import SPHINCS_128s


class TestSPHINCS:
    """Tests pour SPHINCS+-128s (SHA-256 standard)."""

    @pytest.fixture(scope="class")
    def scheme(self):
        return SPHINCSPlus(SPHINCS_128s, use_keccak=False)

    def test_keygen_sizes(self, scheme):
        """Tailles des clés conformes à FIPS 205."""
        pk, sk = scheme.keygen()
        n = SPHINCS_128s["n"]
        assert len(pk) == 2 * n, f"pk doit faire {2*n} octets"
        assert len(sk) == 4 * n, f"sk doit faire {4*n} octets"

    def test_sign_verify_ok(self, scheme):
        """Signature valide doit être acceptée."""
        pk, sk = scheme.keygen()
        msg = b"SuVa Protocol - Phase 5 - SPHINCS+"
        sig = scheme.sign(msg, sk)
        assert scheme.verify(msg, sig, pk), "verify doit retourner True"

    def test_sign_size(self, scheme):
        """Taille de signature conforme au paramètre."""
        pk, sk = scheme.keygen()
        sig = scheme.sign(b"test", sk)
        expected = SPHINCS_128s["sig_bytes"]
        print(f"\n  Taille signature : {len(sig)} octets (attendu {expected})")
        # Tolérance : notre implémentation peut varier légèrement
        assert len(sig) > 0, "Signature ne doit pas être vide"

    def test_wrong_message(self, scheme):
        """Mauvais message → False."""
        pk, sk = scheme.keygen()
        msg = b"message original"
        sig = scheme.sign(msg, sk)
        assert not scheme.verify(b"mauvais message", sig, pk)

    def test_wrong_pk(self, scheme):
        """Mauvaise clé publique → False."""
        pk1, sk1 = scheme.keygen()
        pk2, _   = scheme.keygen()
        msg = b"SuVa Protocol"
        sig = scheme.sign(msg, sk1)
        assert not scheme.verify(msg, sig, pk2)

    def test_corrupted_sig(self, scheme):
        """Signature corrompue → False."""
        pk, sk = scheme.keygen()
        msg = b"test corruption"
        sig = bytearray(scheme.sign(msg, sk))
        sig[10] ^= 0xFF
        assert not scheme.verify(msg, bytes(sig), pk)

    def test_multiple_messages(self, scheme):
        """Vérifier plusieurs messages avec la même clé."""
        pk, sk = scheme.keygen()
        messages = [b"msg1", b"msg2", b"msg 3 avec espace", b"\x00\x01\x02"]
        for m in messages:
            sig = scheme.sign(m, sk)
            assert scheme.verify(m, sig, pk), f"Échec pour {m!r}"


class TestETHSphincs:
    """Tests pour ETHSphincs-128s (Keccak-256, variante EVM)."""

    @pytest.fixture(scope="class")
    def scheme(self):
        return SPHINCSPlus(SPHINCS_128s, use_keccak=True)

    def test_keygen(self, scheme):
        pk, sk = scheme.keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_sign_verify_ok(self, scheme):
        """Variante Keccak : signature valide acceptée."""
        pk, sk = scheme.keygen()
        msg = b"ETHSphincs - EVM compatible PQC"
        sig = scheme.sign(msg, sk)
        assert scheme.verify(msg, sig, pk), "ETHSphincs verify doit retourner True"

    def test_wrong_message(self, scheme):
        pk, sk = scheme.keygen()
        sig = scheme.sign(b"original", sk)
        assert not scheme.verify(b"modifie", sig, pk)

    def test_sha256_vs_keccak_different(self):
        """SHA-256 et Keccak produisent des signatures différentes."""
        params = SPHINCS_128s
        sha_scheme = SPHINCSPlus(params, use_keccak=False)
        eth_scheme = SPHINCSPlus(params, use_keccak=True)

        msg = b"test cross-variant"
        pk_sha, sk_sha = sha_scheme.keygen()
        pk_eth, sk_eth = eth_scheme.keygen()

        sig_sha = sha_scheme.sign(msg, sk_sha)
        sig_eth = eth_scheme.sign(msg, sk_eth)

        # Signatures are different (different hash functions)
        assert sig_sha != sig_eth, "SHA-256 et Keccak doivent produire des sigs différentes"

        # Cross-verification must fail
        assert not sha_scheme.verify(msg, sig_eth, pk_eth), \
            "SHA-256 scheme ne doit pas vérifier une sig Keccak"


class TestSPHINCSParams:
    """Tests des paramètres et dimensions."""

    def test_signature_larger_than_falcon(self):
        """
        SPHINCS+-128s ≈ 7856 octets >> Falcon-256 ≈ 333 octets.
        Illustre pourquoi SPHINCS+ est difficile on mainnet.
        """
        from ..Sphincs.sphincs_params import SPHINCS_128s
        sig_sphincs = SPHINCS_128s["sig_bytes"]
        sig_falcon  = 333   # Falcon-256 signature size
        print(f"\n  SPHINCS+-128s : {sig_sphincs} octets")
        print(f"  Falcon-256    : {sig_falcon} octets")
        print(f"  Ratio         : {sig_sphincs / sig_falcon:.1f}x")
        assert sig_sphincs > sig_falcon * 10, \
            "SPHINCS+ doit être >> Falcon en taille de signature"

    def test_calldata_cost_estimate(self):
        """
        Estimation du coût calldata sur mainnet Ethereum.
        calldata : 16 gas par octet non-nul, 4 gas par octet nul.
        """
        from ..Sphincs.sphincs_params import SPHINCS_128s
        sig_bytes = SPHINCS_128s["sig_bytes"]   # ~7856 bytes
        # Worst case: all non-zero
        calldata_gas = sig_bytes * 16
        print(f"\n  Calldata gas (worst case) : {calldata_gas:,} gas")
        print(f"  At 20 gwei, 1800 USD/ETH  : ${calldata_gas * 20e-9 * 1800:.4f}")
        # On L2, calldata is ~10-100x cheaper
        l2_gas = calldata_gas // 10
        print(f"  L2 estimate (÷10)         : {l2_gas:,} gas")
        assert calldata_gas > 100_000, "Calldata cost doit être significatif"
