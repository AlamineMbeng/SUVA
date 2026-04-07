"""
ETHFalcon : Falcon avec KeccakPRNG à la place de SHAKE256.
Même principe qu'ETHDilithium vs Dilithium.

Sign ET Verify utilisent tous les deux KeccakPRNG.
On sous-classe falcon_sign.Falcon pour patcher __hash_to_point__
afin que sign() utilise aussi Keccak.
"""

import sys
import os

_REF_DIR = os.path.join(os.path.dirname(__file__), "falcon_ref")
if _REF_DIR not in sys.path:
    sys.path.insert(0, _REF_DIR)

from falcon_sign import Falcon as _FalconRef
from common import q as _Q

from .falcon_core import FalconCore
from .falcon_hash import hash_to_point_keccak
from .falcon_params import FALCON_256, FALCON_512


class _ETHFalconRef(_FalconRef):
    """
    Sous-classe de falcon_sign.Falcon.
    Remplace SHAKE256 par KeccakPRNG dans __hash_to_point__.
    Affecte sign() et verify() de la classe de référence.

    Note : dans falcon_sign.py, __hash_to_point__(message, salt)
           injecte salt EN PREMIER, puis message.
           → on appelle hash_to_point_keccak(salt, message, ...)
    """

    def __hash_to_point__(self, message: bytes, salt: bytes) -> list:
        return hash_to_point_keccak(salt, message, self.param.n, _Q)


class ETHFalcon(FalconCore):
    """
    ETHFalcon complet.
    - keygen : identique (non affecté par le hash)
    - sign   : utilise KeccakPRNG via _ETHFalconRef
    - verify : utilise KeccakPRNG via FalconCore + hash_to_point_keccak
    """

    def __init__(self, params: dict):
        super().__init__(params, hash_fn=hash_to_point_keccak)
        self._ref = _ETHFalconRef(self.n)

    def keygen(self):
        sk, vk = self._ref.keygen()
        return sk, vk

    def sign(self, sk, message: bytes) -> bytes:
        return self._ref.sign(sk, message)


# Instances prêtes à l'emploi
ETHFalcon256 = ETHFalcon(FALCON_256)
ETHFalcon512 = ETHFalcon(FALCON_512)
