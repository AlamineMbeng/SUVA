"""
Tests unitaires phase 2 - ETHFalcon
Lance avec : cd python-ref && python -m pytest Falcon_dilithium_py/tests/test_falcon.py -v
"""

import sys, os
import unittest

#Ajouter falcon_ref au path pour poly_mul de référence
_REF = os.path.join(os.path.dirname(__file__), '..', 'Falcon_falcon', 'falcon_ref')
sys.path.insert(0, os.path.abspath(_REF))

from ntt import mul_zq, sub_zq
from ..Falcon_falcon.falcon_poly import poly_mul, poly_sub, norm_sq
from ..Falcon_falcon.falcon_hash import hash_to_point_shake, hash_to_point_keccak
from ..Falcon_falcon.falcon_eth  import ETHFalcon256

# TEST A : Arithmétique polynoiale

class TestFalconPoly(unittest.TestCase):

    def test_poly_mul(self):
        import os as _os
        a = [_os.urandom(1)[0] % 12289 for _ in range(256)]
        b = [_os.urandom(1)[0] % 12289 for _ in range(256)]

        our = poly_mul(a, b)
        theirs = list(mul_zq(a, b))
        self.assertEqual(our, theirs, "poly_mul diverge de mul_zq")

    def test_poly_sub_matches_ref(self):
        import os as _os
        a = [_os.urandom(1)[0] % 12289 for _ in range(256)]
        b = [_os.urandom(1)[0] % 12289 for _ in range(256)]

        our = poly_sub(a, b)
        theirs = list(sub_zq(a, b))
        self.assertEqual(our, theirs, "poly_sub diverge de sub_zq")

    def test_norm_sq_centered(self):
         q = 12289
         s = [0, q-1, q//2, q//2+1]
         expected = 0 + 1 + 6144**2 +6144**2

         s_padded = s + [0] * 252
         result = norm_sq(s_padded)
         self.assertEqual(result, expected,)


# TEST B - HashToPoint

class TestFalconHash(unittest.TestCase):


    def test_hash_length(self):

        salt = bytes(range(40))
        msg = b"SuVA test"

        t_shake = hash_to_point_shake(salt, msg, 256)
        t_keccak = hash_to_point_keccak(salt, msg, 256)
        self.assertEqual(len(t_shake), 256)
        self.assertEqual(len(t_keccak), 256)

    def test_hash_range(self):

        salt = os.urandom(40)
        msg = b"Suva range test"

        for t in [hash_to_point_shake(salt, msg, 256), hash_to_point_keccak(salt, msg, 256)]:
            self.assertTrue(all(0 <= c < 12289 for c in t),  "Coefficient hors de [0, q-1]")

    def test_shake_ne_keccak(self):
        """SHAKE et Keccak doivent produire des résultats différents."""
        import os
        salt = os.urandom(40)
        msg = b"diff test"
        t_s = hash_to_point_shake(salt, msg, 256)
        t_k = hash_to_point_keccak(salt, msg, 256)
        self.assertNotEqual(t_s, t_k,
                            "SHAKE et Keccak ne doivent pas produire le même résultat")

    def test_keccak_deterministic(self):
        """Même entrée → même sortie (déterminisme)."""
        salt = bytes(40)
        msg = b"deterministic"
        t1 = hash_to_point_keccak(salt, msg, 256)
        t2 = hash_to_point_keccak(salt, msg, 256)
        self.assertEqual(t1, t2)


# ─────────────────────────────────────────────
# TEST C — ETHFalcon end-to-end
# ─────────────────────────────────────────────

class TestETHFalcon(unittest.TestCase):

    def test_verify_valid(self):
        """Signature valide → True."""
        sk, vk = ETHFalcon256.keygen()
        msg = b"SuVa Protocol Phase 2"
        sig = ETHFalcon256.sign(sk, msg)
        self.assertTrue(ETHFalcon256.verify(vk, msg, sig))

    def test_verify_wrong_msg(self):
        """Mauvais message → False."""
        sk, vk = ETHFalcon256.keygen()
        sig = ETHFalcon256.sign(sk, b"correct")
        self.assertFalse(ETHFalcon256.verify(vk, b"wrong", sig))

    def test_verify_wrong_pk(self):
        """Mauvaise clé publique → False."""
        sk, vk = ETHFalcon256.keygen()
        _, vk2 = ETHFalcon256.keygen()
        msg = b"SuVa test"
        sig = ETHFalcon256.sign(sk, msg)
        self.assertFalse(ETHFalcon256.verify(vk2, msg, sig))

    def test_verify_corrupted_sig(self):
        """Signature corrompue → False."""
        sk, vk = ETHFalcon256.keygen()
        msg = b"SuVa test"
        sig = bytearray(ETHFalcon256.sign(sk, msg))
        sig[25] ^= 0xFF  # flip 8 bits dans le salt
        self.assertFalse(ETHFalcon256.verify(vk, msg, bytes(sig)))

    def test_sig_size(self):
        """Taille signature Falcon-256 doit être 356 octets exactement."""
        sk, vk = ETHFalcon256.keygen()
        sig = ETHFalcon256.sign(sk, b"size test")
        self.assertEqual(len(sig), 356, f"Taille inattendue : {len(sig)}")

    def test_vk_size(self):
        """Taille clé publique doit être 448 octets (256 * 14 / 8)."""
        _, vk = ETHFalcon256.keygen()
        self.assertEqual(len(vk), 448, f"Taille VK inattendue : {len(vk)}")

    def test_multiple_runs(self):
        """5 keygen/sign/verify consécutifs doivent tous passer."""
        for i in range(5):
            sk, vk = ETHFalcon256.keygen()
            msg = f"run {i}".encode()
            sig = ETHFalcon256.sign(sk, msg)
            self.assertTrue(ETHFalcon256.verify(vk, msg, sig),
                            f"Échec au run {i}")


if __name__ == "__main__":
    unittest.main(verbosity=2)