"""
FalconCore : keygen / sign / verify pour Falcon et ETHFalcon.

- keygen et sign : délégués à falcon_ref (gère NTRU trapdoor + FFT sampling)
- verify : réécrit manuellement pour correspondre exactement au contrat Solidity

Vérification Falcon (miroir de falcon_sign.py Falcon.verify) :
  Données : vk (clé publique bytes), message, signature bytes
  1. Décoder vk → h (polynôme de n coefficients)
  2. salt  = signature[1 : 41]
  3. enc_s = signature[41 :]
  4. s1 = decompress(enc_s)
  5. t  = HashToPoint(salt || message)
  6. s0 = t - s1*h  (mod q, mod X^n+1)
  7. Vérifier ||s0||^2 + ||s1||^2 <= sig_bound
"""

import sys
import os

# Ajouter falcon_ref au sys.path pour ses imports flat
_REF_DIR = os.path.join(os.path.dirname(__file__), "falcon_ref")
if _REF_DIR not in sys.path:
    sys.path.insert(0, _REF_DIR)

from falcon_sign import Falcon as _FalconRef                    # keygen + sign
from encoding import decompress                                  # décompresser s1
from falcon_sign import deserialize_to_poly, HEAD_LEN, SALT_LEN  # helpers

from .falcon_hash import hash_to_point_shake
from .falcon_poly import poly_mul, poly_sub, norm_sq
from .falcon_params import Q


class FalconCore:
    """
    Classe de base Falcon.
    hash_fn : fonction HashToPoint utilisée pour verify.
              Par défaut = SHAKE256 (Falcon standard).
              Pour ETHFalcon, passer hash_to_point_keccak.
    """

    def __init__(self, params: dict, hash_fn=hash_to_point_shake):
        self.n         = params["n"]
        self.q         = params["q"]
        self.sig_bound = params["sig_bound"]
        self.nonce_len = params["nonce_len"]
        self.sig_bytelen = params["sig_bytelen"]
        self.hash_fn   = hash_fn
        self._ref      = _FalconRef(self.n)   # instance falcon_ref pour keygen/sign

    # ------------------------------------------------------------------
    # KEYGEN — délégué à falcon_ref
    # ------------------------------------------------------------------
    def keygen(self):
        """
        Retourne (sk, vk).
        sk  : clé privée (opaque, tuple interne falcon_ref)
        vk  : clé publique sérialisée (bytes, 448B pour n=256)
        """
        sk, vk = self._ref.keygen()
        return sk, vk

    # ------------------------------------------------------------------
    # SIGN — délégué à falcon_ref (utilise SHAKE, signatures identiques)
    # ------------------------------------------------------------------
    def sign(self, sk, message: bytes) -> bytes:
        """
        Signe message avec sk.
        Retourne la signature brute.
        Format : [header(1B)] [salt(40B)] [s1 compressé]
        """
        return self._ref.sign(sk, message)

    # ------------------------------------------------------------------
    # VERIFY — réécrit pour correspondre au contrat Solidity
    # ------------------------------------------------------------------
    def verify(self, vk: bytes, message: bytes, sig_bytes: bytes) -> bool:
        """
        Vérifie la signature. Utilise self.hash_fn pour HashToPoint.
        C'est cette logique que ZKNOX_ethfalcon.sol reproduit.

        Étapes :
          1. Décoder vk → h
          2. Extraire salt et enc_s de sig_bytes
          3. Décompresser enc_s → s1
          4. t = HashToPoint(salt, message)
          5. s0 = t - s1*h mod (q, X^n+1)
          6. vérifier norme
        """
        try:
            # Étape 1
            h = deserialize_to_poly(vk, self.n)

            # Étape 2
            salt  = sig_bytes[HEAD_LEN : HEAD_LEN + SALT_LEN]
            enc_s = sig_bytes[HEAD_LEN + SALT_LEN :]

            # Étape 3 : décompresser s1
            enc_s_len = self.sig_bytelen - HEAD_LEN - SALT_LEN
            s1 = decompress(enc_s, enc_s_len, self.n)
            if s1 is False:
                return False

        except Exception:
            return False

        # Étape 4 : HashToPoint avec la fonction choisie (SHAKE ou Keccak)
        t = self.hash_fn(salt, message, self.n, self.q)

        # Étape 5 : s0 = t - s1*h mod q
        s1h = poly_mul(s1, h, self.q)
        s0  = poly_sub(t, s1h, self.q)
        # Centrer s0 dans (-q/2, q/2]
        half_q = self.q >> 1
        s0 = [(c + half_q) % self.q - half_q for c in s0]

        # Étape 6 : vérifier norme
        n_sq = norm_sq(s0, self.q) + norm_sq(s1, self.q)
        if n_sq > self.sig_bound:
            return False

        return True
