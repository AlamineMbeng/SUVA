"""
HashToPoint : (salt || message) → polynôme de n éléments dans Z_q.

C'est le seul endroit où Falcon utilise SHAKE256.
ETHFalcon remplace SHAKE256 par KeccakPRNG (compatible on-chain EVM).

Algorithme identique pour les deux versions :
  1. Initialiser XOF avec (salt || message)
  2. Lire 2 octets → entier 16 bits BIG-ENDIAN : (b0 << 8) | b1
  3. Rejection sampling : garder si val < k*q  (k=5, seuil=61445)
  4. Répéter jusqu'à n éléments

Note byte order : BIG-ENDIAN, conforme à falcon_sign.py ligne :
  elt = (twobytes[0] << 8) + twobytes[1]
"""

from Crypto.Hash import SHAKE256
from ..Falcon_keccak_prng.keccak_prng_wrapper import Keccak256PRNG

Q = 12289
# k = floor(65536 / q) = floor(65536 / 12289) = 5
# seuil = k * q = 5 * 12289 = 61445
_K = (1 << 16) // Q
_THRESHOLD = _K * Q  # 61445


def hash_to_point_shake(salt: bytes, message: bytes, n: int, q: int = Q) -> list:
    """
    HashToPoint standard Falcon — SHAKE256.
    Reproduction exacte de Falcon.__hash_to_point__ dans falcon_sign.py.
    """
    shake = SHAKE256.new()
    shake.update(salt)
    shake.update(message)

    k = (1 << 16) // q
    threshold = k * q

    hashed = []
    while len(hashed) < n:
        two_bytes = shake.read(2)
        elt = (two_bytes[0] << 8) + two_bytes[1]   # BIG-ENDIAN
        if elt < threshold:
            hashed.append(elt % q)

    return hashed[:n]


def hash_to_point_keccak(salt: bytes, message: bytes, n: int, q: int = Q) -> list:
    """
    HashToPoint ETHFalcon — KeccakPRNG à la place de SHAKE256.
    MÊME algorithme, MÊME byte order (big-endian).
    C'est ce que ZKNOX_ethfalcon.sol:_hashToPoint() reproduit.
    """
    prng = Keccak256PRNG()
    prng.inject(salt + message)
    prng.flip()

    k = (1 << 16) // q
    threshold = k * q

    hashed = []
    while len(hashed) < n:
        two_bytes = prng.read(2)
        elt = (two_bytes[0] << 8) + two_bytes[1]   # BIG-ENDIAN
        if elt < threshold:
            hashed.append(elt % q)

    return hashed[:n]
