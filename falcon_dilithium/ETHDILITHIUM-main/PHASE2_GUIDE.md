# Phase 2 — ETHFalcon : Guide de développement

**Auteur :** Mohamed Lamine MBENGUE
**Projet :** SuVa Protocol — Post-Quantum Signatures on EVM
**Objectif :** Intégrer Falcon/ETHFalcon et mesurer le gas on-chain

---

## Contexte rapide

| Schéma | Hash interne | Gas estimé | Taille sig |
|---|---|---|---|
| Dilithium | SHAKE-256 | 13.42M | ~2420 B |
| ETHDilithium | Keccak-256 | **6.58M** | ~2420 B |
| Falcon | SHAKE-256 | ? | ~666 B |
| **ETHFalcon** | **Keccak-256** | **? (objectif)** | **~666 B** |

Falcon a des signatures 3.6x plus courtes → on s'attend à moins de gas.

---

## Architecture des fichiers à créer

```
python-ref/Falcon_dilithium_py/
├── Falcon_falcon/                    [ÉTAPE 2 — Python]
│   ├── __init__.py
│   ├── falcon_params.py              paramètres (n, q, beta)
│   ├── falcon_hash.py                HashToPoint SHAKE + Keccak
│   ├── falcon_poly.py                arithmétique polynomiale
│   ├── falcon_core.py                keygen / sign / verify
│   └── falcon_eth.py                 ETHFalcon (Keccak)
├── tests/
│   └── test_falcon.py                [ÉTAPE 2 — Tests Python]
└── generate_falcon_test_vectors.py   [ÉTAPE 4 — Génération]

src/
├── ZKNOX_falcon_params.sol           [ÉTAPE 3 — Solidity]
├── ZKNOX_falcon_poly.sol
└── ZKNOX_ethfalcon.sol

test/
└── ZKNOX_ethfalcon.t.sol             [GÉNÉRÉ par l'étape 4]
```

---

## Pré-requis

```bash
# Installer falcon-py (implémentation NIST de Thomas Prest)
cd python-ref/
pip install falcon-py

# Vérifier l'installation
python -c "import falcon; sk = falcon.SecretKey(256); print('OK')"
```

Ajouter dans `python-ref/requirements.txt` :
```
falcon-py
```

---

## ÉTAPE 2 — Module Python

### Ordre de création

1. `falcon_params.py`
2. `falcon_hash.py`
3. `falcon_poly.py`
4. `falcon_core.py`
5. `falcon_eth.py`
6. `__init__.py`

---

### Fichier 1 : `Falcon_falcon/falcon_params.py`

```python
"""
Paramètres Falcon — SuVa Phase 2.
q = 12289 (différent de Dilithium q = 8380417)
On utilise Falcon-256 (n=256) pour minimiser le gas on-chain.
"""

FALCON_256 = {
    "n": 256,
    "q": 12289,
    "beta_sq": 34034726,   # ||s1||^2 + ||s2||^2 <= beta_sq
    "nonce_len": 40,       # octets dans la signature
}

FALCON_512 = {
    "n": 512,
    "q": 12289,
    "beta_sq": 34034726,
    "nonce_len": 40,
}

Q = 12289
```

**Pourquoi n=256 ?** Signatures plus courtes → moins de calldata → moins de gas.

---

### Fichier 2 : `Falcon_falcon/falcon_hash.py`

> C'est LE fichier central. C'est ici que SHAKE devient Keccak pour ETHFalcon.
> Le contrat Solidity `ZKNOX_ethfalcon.sol` devra reproduire exactement
> la fonction `hash_to_point_keccak`.

```python
"""
HashToPoint : (nonce || msg) → polynôme t de n éléments dans Z_q.

Falcon utilise SHAKE256 pour cette étape.
ETHFalcon remplace SHAKE256 par KeccakPRNG (compatible on-chain EVM).

Algorithme (identique, seul le XOF change) :
  1. Initialiser XOF avec (nonce || msg)
  2. Lire 2 octets à la fois → entier 16 bits
  3. Rejection sampling : garder si val < 5*q (= 61445)
  4. Répéter jusqu'à avoir n éléments
"""

from hashlib import shake_256
from ..Falcon_keccak_prng.keccak_prng_wrapper import Keccak256PRNG


def hash_to_point_shake(nonce: bytes, msg: bytes, n: int, q: int) -> list:
    """Version standard Falcon — SHAKE256."""
    xof = shake_256()
    xof.update(nonce + msg)

    t = []
    buf_size = 2 * n * 4
    buf = xof.digest(buf_size)
    idx = 0

    while len(t) < n:
        if idx + 2 > len(buf):
            buf_size *= 2
            buf = xof.digest(buf_size)

        # Lire 2 octets → entier 16 bits little-endian
        val = buf[idx] | (buf[idx + 1] << 8)
        idx += 2

        # Rejection sampling : seuil = floor(65536/q)*q = 5*12289 = 61445
        if val < 5 * q:
            t.append(val % q)

    return t[:n]


def hash_to_point_keccak(nonce: bytes, msg: bytes, n: int, q: int) -> list:
    """
    Version ETHFalcon — KeccakPRNG.
    MÊME algorithme que SHAKE, seul le XOF change.
    C'est ce que ZKNOX_ethfalcon.sol:_hashToPoint() reproduit.
    """
    prng = Keccak256PRNG()
    prng.inject(nonce + msg)
    prng.flip()

    t = []
    while len(t) < n:
        raw = prng.read(2)
        val = raw[0] | (raw[1] << 8)
        if val < 5 * q:
            t.append(val % q)

    return t[:n]
```

---

### Fichier 3 : `Falcon_falcon/falcon_poly.py`

```python
"""
Opérations sur les polynômes dans Z_q[X]/(X^n + 1).
q = 12289, n = 256.

Règle clé : X^256 ≡ -1 (mod X^256 + 1)
→ si i+j >= n lors d'une multiplication, le signe s'inverse.
"""

Q = 12289


def poly_add(a: list, b: list, q: int = Q) -> list:
    """Addition coefficient par coefficient mod q."""
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: list, b: list, q: int = Q) -> list:
    """Soustraction coefficient par coefficient mod q."""
    return [(x - y) % q for x, y in zip(a, b)]


def poly_mul_schoolbook(a: list, b: list, q: int = Q) -> list:
    """
    Multiplication dans Z_q[X]/(X^n + 1) — schoolbook O(n²).
    Utilisée côté Python pour les tests.
    Le contrat Solidity fait la même chose.

    Pour i+j >= n : signe inversé car X^n ≡ -1
    """
    n = len(a)
    result = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            prod = (a[i] * b[j]) % q
            if i + j >= n:
                # X^(i+j) = X^(i+j-n) * X^n ≡ -X^(i+j-n)
                result[idx] = (result[idx] - prod) % q
            else:
                result[idx] = (result[idx] + prod) % q
    return result


def norm_squared(s: list, q: int = Q) -> int:
    """
    Norme L2 au carré — coefficients centrés autour de 0.
    Si c > q/2 : c représente c - q (valeur négative).
    """
    half_q = q // 2
    total = 0
    for c in s:
        if c > half_q:
            c = c - q
        total += c * c
    return total
```

---

### Fichier 4 : `Falcon_falcon/falcon_core.py`

```python
"""
FalconBase : keygen / sign / verify.

- keygen et sign : délégués à falcon-py (gère la complexité NTRU + FFT)
- verify : écrit manuellement pour correspondre exactement au contrat Solidity

Vérification Falcon :
  Entrée  : pk (h polynomial), msg, sig_bytes
  1. Décoder sig → (nonce, s2)
  2. t = HashToPoint(nonce || msg)
  3. s1 = t - h*s2  (mod q, mod X^n+1)
  4. Vérifier ||s1||^2 + ||s2||^2 <= beta_sq
"""

import falcon as falcon_lib   # pip install falcon-py
from .falcon_hash import hash_to_point_shake
from .falcon_poly import poly_mul_schoolbook, poly_sub, norm_squared
from .falcon_params import Q


class FalconBase:

    def __init__(self, params: dict, hash_fn=hash_to_point_shake):
        self.n        = params["n"]
        self.q        = params["q"]
        self.beta_sq  = params["beta_sq"]
        self.nonce_len = params["nonce_len"]
        self.hash_fn  = hash_fn

    # ------------------------------------------------------------------
    # KEYGEN
    # ------------------------------------------------------------------
    def keygen(self):
        """
        Retourne (pk, sk).
        pk.h = polynôme public, liste de n coefficients dans Z_q
        sk   = objet SecretKey de falcon-py
        """
        sk = falcon_lib.SecretKey(self.n)
        pk = falcon_lib.PublicKey(sk)
        return pk, sk

    # ------------------------------------------------------------------
    # SIGN
    # ------------------------------------------------------------------
    def sign(self, sk, msg: bytes) -> bytes:
        """
        Signe msg. Retourne les octets bruts de la signature.
        Format : [header(1B)] [nonce(40B)] [s2 compressé]
        """
        return sk.sign(msg)

    # ------------------------------------------------------------------
    # VERIFY
    # ------------------------------------------------------------------
    def verify(self, pk, msg: bytes, sig_bytes: bytes) -> bool:
        """
        Vérifie la signature.
        C'est cette logique que ZKNOX_ethfalcon.sol reproduit.
        """
        try:
            nonce, s2 = self._decode_signature(sig_bytes)
        except Exception:
            return False

        # Étape 2 : HashToPoint
        t = self.hash_fn(nonce, msg, self.n, self.q)

        # Étape 3 : s1 = t - h*s2
        h_coeffs = list(pk.h)
        hs2 = poly_mul_schoolbook(h_coeffs, s2, self.q)
        s1  = poly_sub(t, hs2, self.q)

        # Étape 4 : vérifier la norme
        norm_sq = norm_squared(s1, self.q) + norm_squared(s2, self.q)
        if norm_sq > self.beta_sq:
            return False

        return True

    # ------------------------------------------------------------------
    # DÉCODAGE SIGNATURE
    # ------------------------------------------------------------------
    def _decode_signature(self, sig_bytes: bytes):
        """
        Décode la signature en (nonce, s2).

        Format Falcon :
          sig_bytes[0]          = header (1 octet, ignoré pour l'instant)
          sig_bytes[1..41]      = nonce (40 octets)
          sig_bytes[41..]       = s2 compressé (encoding Falcon)

        On utilise falcon_lib.decompress pour décoder s2.
        """
        if len(sig_bytes) < 1 + self.nonce_len:
            raise ValueError("Signature trop courte")

        nonce  = sig_bytes[1 : 1 + self.nonce_len]
        s_part = sig_bytes[1 + self.nonce_len :]

        # Décompresser s2 via falcon-py
        s2_signed = falcon_lib.decompress(s_part, self.n)
        if s2_signed is None:
            raise ValueError("Décompression de s2 échouée")

        # Convertir coefficients signés en non-signés mod q
        s2 = [c % self.q for c in s2_signed]

        return nonce, s2
```

---

### Fichier 5 : `Falcon_falcon/falcon_eth.py`

```python
"""
ETHFalcon : Falcon avec KeccakPRNG au lieu de SHAKE256.
Même principe qu'ETHDilithium vs Dilithium.
"""

from .falcon_core import FalconBase
from .falcon_hash import hash_to_point_keccak
from .falcon_params import FALCON_256, FALCON_512


class ETHFalcon(FalconBase):
    """ETHFalcon : KeccakPRNG pour HashToPoint."""

    def __init__(self, params: dict):
        super().__init__(params, hash_fn=hash_to_point_keccak)


# Instances prêtes à l'emploi
ETHFalcon256 = ETHFalcon(FALCON_256)
ETHFalcon512 = ETHFalcon(FALCON_512)
```

---

### Fichier 6 : `Falcon_falcon/__init__.py`

```python
from .falcon_eth import ETHFalcon256, ETHFalcon512
from .falcon_core import FalconBase
from .falcon_params import FALCON_256, FALCON_512

__all__ = ["ETHFalcon256", "ETHFalcon512", "FalconBase", "FALCON_256", "FALCON_512"]
```

---

## ÉTAPE 2 — Tests Python

### Fichier 7 : `tests/test_falcon.py`

```python
"""
Tests unitaires pour Falcon / ETHFalcon.
Lance avec : python -m pytest tests/test_falcon.py -v
"""

import unittest
from ..Falcon_falcon.falcon_eth import ETHFalcon256


class TestETHFalcon(unittest.TestCase):

    # ------------------------------------------------------------------
    # TEST 1 : keygen → sign → verify doit retourner True
    # ------------------------------------------------------------------
    def test_verify_ok(self):
        pk, sk = ETHFalcon256.keygen()
        msg = b"SuVa Protocol - Phase 2 - Falcon"
        sig = ETHFalcon256.sign(sk, msg)
        result = ETHFalcon256.verify(pk, msg, sig)
        self.assertTrue(result, "verify doit retourner True pour une signature valide")

    # ------------------------------------------------------------------
    # TEST 2 : mauvaise clé publique → False
    # ------------------------------------------------------------------
    def test_wrong_pk(self):
        pk, sk = ETHFalcon256.keygen()
        pk_autre, _ = ETHFalcon256.keygen()
        msg = b"SuVa Protocol - Phase 2 - Falcon"
        sig = ETHFalcon256.sign(sk, msg)
        result = ETHFalcon256.verify(pk_autre, msg, sig)
        self.assertFalse(result, "Mauvaise PK doit être rejetée")

    # ------------------------------------------------------------------
    # TEST 3 : mauvais message → False
    # ------------------------------------------------------------------
    def test_wrong_msg(self):
        pk, sk = ETHFalcon256.keygen()
        msg = b"SuVa Protocol - Phase 2 - Falcon"
        sig = ETHFalcon256.sign(sk, msg)
        result = ETHFalcon256.verify(pk, b"message different", sig)
        self.assertFalse(result, "Mauvais message doit être rejeté")

    # ------------------------------------------------------------------
    # TEST 4 : signature corrompue → False
    # ------------------------------------------------------------------
    def test_corrupted_sig(self):
        pk, sk = ETHFalcon256.keygen()
        msg = b"SuVa Protocol - Phase 2 - Falcon"
        sig = ETHFalcon256.sign(sk, msg)

        sig_corrompu = bytearray(sig)
        sig_corrompu[20] ^= 0xFF   # flip 8 bits au milieu du nonce
        result = ETHFalcon256.verify(pk, msg, bytes(sig_corrompu))
        self.assertFalse(result, "Signature corrompue doit être rejetée")

    # ------------------------------------------------------------------
    # TEST 5 : taille des structures (utile pour estimer le gas calldata)
    # ------------------------------------------------------------------
    def test_sizes(self):
        pk, sk = ETHFalcon256.keygen()
        msg = b"SuVa Protocol - Phase 2 - Falcon"
        sig = ETHFalcon256.sign(sk, msg)

        print(f"\n--- Tailles ETHFalcon-256 ---")
        print(f"  Signature   : {len(sig)} octets")
        print(f"  Clé pub (h) : {len(list(pk.h)) * 2} octets (~{len(list(pk.h))} coefficients x 2B)")
        print(f"  Message     : {len(msg)} octets")

        # Falcon-256 doit produire des signatures courtes
        self.assertLess(len(sig), 700, "Signature Falcon-256 doit être < 700 octets")

    # ------------------------------------------------------------------
    # TEST 6 : robustesse sur plusieurs runs (test randomness)
    # ------------------------------------------------------------------
    def test_multiple_runs(self):
        for i in range(5):
            pk, sk = ETHFalcon256.keygen()
            msg = b"test run " + str(i).encode()
            sig = ETHFalcon256.sign(sk, msg)
            self.assertTrue(ETHFalcon256.verify(pk, msg, sig), f"Échec au run {i}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

**Commande pour lancer les tests :**
```bash
cd python-ref/
python -m pytest Falcon_dilithium_py/tests/test_falcon.py -v
```

**Sortie attendue :**
```
test_verify_ok          PASSED
test_wrong_pk           PASSED
test_wrong_msg          PASSED
test_corrupted_sig      PASSED
test_sizes              PASSED
test_multiple_runs      PASSED
--- Tailles ETHFalcon-256 ---
  Signature   : ~333 octets
  Clé pub (h) : ~512 octets
```

---

## ÉTAPE 3 — Contrats Solidity

### Fichier 8 : `src/ZKNOX_falcon_params.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Paramètres Falcon-256 pour ZKNOX_ethfalcon.sol
// q = 12289 (différent de Dilithium q = 8380417)
uint256 constant FALCON_Q         = 12289;
uint256 constant FALCON_N         = 256;
uint256 constant FALCON_BETA_SQ   = 34034726;  // borne norme au carré
uint256 constant FALCON_NONCE_LEN = 40;        // octets
uint256 constant FALCON_THRESHOLD = 61445;     // 5 * 12289 pour rejection sampling
```

---

### Fichier 9 : `src/ZKNOX_falcon_poly.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_params.sol";

/**
 * Opérations polynomiales dans Z_12289[X]/(X^256 + 1).
 *
 * Règle : X^256 ≡ -1
 * → si i+j >= 256 lors d'une multiplication, signe inversé.
 *
 * Version schoolbook O(n²) — à optimiser avec NTT si gas trop élevé.
 */
library FalconPoly {

    /**
     * Multiplication : a * b mod (X^256 + 1, q)
     */
    function mul(uint256[256] memory a, uint256[256] memory b)
        internal
        pure
        returns (uint256[256] memory result)
    {
        uint256 q = FALCON_Q;
        for (uint256 i = 0; i < 256; i++) {
            for (uint256 j = 0; j < 256; j++) {
                uint256 idx  = (i + j) % 256;
                uint256 prod = mulmod(a[i], b[j], q);
                if (i + j >= 256) {
                    // X^(i+j) = -X^(i+j-256) → soustraire
                    result[idx] = (result[idx] + q - prod) % q;
                } else {
                    result[idx] = (result[idx] + prod) % q;
                }
            }
        }
    }

    /**
     * Soustraction : a - b mod q
     */
    function sub(uint256[256] memory a, uint256[256] memory b)
        internal
        pure
        returns (uint256[256] memory result)
    {
        uint256 q = FALCON_Q;
        for (uint256 i = 0; i < 256; i++) {
            result[i] = (a[i] + q - b[i]) % q;
        }
    }

    /**
     * Norme L2 au carré — coefficients centrés.
     * Si c > q/2 : c représente c - q (négatif).
     */
    function normSquared(uint256[256] memory s)
        internal
        pure
        returns (uint256 norm_sq)
    {
        uint256 q      = FALCON_Q;
        uint256 half_q = q / 2;
        norm_sq = 0;
        for (uint256 i = 0; i < 256; i++) {
            uint256 c = s[i];
            int256 centered = c > half_q
                ? int256(c) - int256(q)
                : int256(c);
            // centered^2 est toujours positif
            norm_sq += uint256(centered * centered);
        }
    }
}
```

---

### Fichier 10 : `src/ZKNOX_ethfalcon.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_params.sol";
import "./ZKNOX_falcon_poly.sol";

/**
 * ETHFalcon — Vérification Falcon on-chain avec KeccakPRNG.
 *
 * Algorithme (miroir de FalconBase.verify() en Python) :
 *   1. Extraire nonce de la signature
 *   2. t = _hashToPoint(nonce || msg)  ← KeccakPRNG
 *   3. hs2 = h * s2                    ← multiplication polynomiale
 *   4. s1 = t - hs2                    ← soustraction
 *   5. Vérifier ||s1||^2 + ||s2||^2 <= FALCON_BETA_SQ
 */
contract ZKNOX_ethfalcon {

    /**
     * Vérification principale ETHFalcon.
     *
     * @param h    Clé publique : 256 coefficients dans Z_12289
     * @param msg  Message original signé
     * @param sig  Signature : [header(1B)] [nonce(40B)] [s2_raw(512B)]
     */
    function verify(
        uint256[256] calldata h,
        bytes calldata msg,
        bytes calldata sig
    ) external pure returns (bool) {

        // ---- Étape 1 : extraire nonce ----
        uint256 offset = 1; // ignorer header
        require(sig.length >= offset + FALCON_NONCE_LEN + 512, "Signature invalide");

        bytes memory nonce = new bytes(FALCON_NONCE_LEN);
        for (uint256 i = 0; i < FALCON_NONCE_LEN; i++) {
            nonce[i] = sig[offset + i];
        }
        offset += FALCON_NONCE_LEN;

        // ---- Étape 2 : HashToPoint(nonce || msg) ----
        uint256[256] memory t = _hashToPoint(nonce, msg);

        // ---- Étape 3 : décoder s2 ----
        uint256[256] memory s2 = _decodeS2(sig, offset);

        // ---- Étape 4 : hs2 = h * s2, puis s1 = t - hs2 ----
        uint256[256] memory hs2 = FalconPoly.mul(h, s2);
        uint256[256] memory s1  = FalconPoly.sub(t, hs2);

        // ---- Étape 5 : vérifier norme ----
        uint256 norm_sq = FalconPoly.normSquared(s1)
                        + FalconPoly.normSquared(s2);
        if (norm_sq > FALCON_BETA_SQ) return false;

        return true;
    }

    /**
     * HashToPoint : reproduit exactement hash_to_point_keccak() en Python.
     *
     * Algorithme :
     *   state = keccak256(nonce || msg)
     *   loop :
     *     block = keccak256(state || counter)
     *     pour chaque paire d'octets dans block :
     *       val = octet_lo | (octet_hi << 8)
     *       si val < 5*q : t[filled] = val % q; filled++
     *     counter++
     */
    function _hashToPoint(bytes memory nonce, bytes calldata msg)
        internal
        pure
        returns (uint256[256] memory t)
    {
        uint256 q         = FALCON_Q;
        uint256 threshold = FALCON_THRESHOLD; // 5 * 12289 = 61445

        bytes32 state = keccak256(abi.encodePacked(nonce, msg));
        uint64  counter = 0;
        uint256 filled  = 0;

        while (filled < 256) {
            bytes32 block_out = keccak256(abi.encodePacked(state, counter));
            counter++;

            // 32 octets par bloc → 16 paires de 2 octets
            for (uint256 i = 0; i < 32 && filled < 256; i += 2) {
                uint256 val = uint8(block_out[i])
                            | (uint256(uint8(block_out[i + 1])) << 8);
                if (val < threshold) {
                    t[filled] = val % q;
                    filled++;
                }
            }
        }
    }

    /**
     * Décoder s2 depuis la signature.
     * Format : 256 coefficients × uint16 little-endian = 512 octets.
     * (version simplifiée non compressée pour les tests initiaux)
     */
    function _decodeS2(bytes calldata sig, uint256 offset)
        internal
        pure
        returns (uint256[256] memory s2)
    {
        for (uint256 i = 0; i < 256; i++) {
            uint256 lo = uint8(sig[offset + 2 * i]);
            uint256 hi = uint8(sig[offset + 2 * i + 1]);
            s2[i] = lo | (hi << 8);
        }
    }
}
```

---

## ÉTAPE 4 — Script de génération des test vectors

### Fichier 11 : `python-ref/Falcon_dilithium_py/generate_falcon_test_vectors.py`

```python
"""
Génère test/ZKNOX_ethfalcon.t.sol à partir d'une signature ETHFalcon réelle.

Principe :
  1. Python fait keygen + sign + verify (source de vérité)
  2. On exporte h, msg, sig en hex
  3. On les injecte dans un fichier .t.sol que Foundry va tester

Usage :
  cd python-ref/
  python -m Falcon_dilithium_py.generate_falcon_test_vectors
"""

from .Falcon_falcon.falcon_eth import ETHFalcon256
import struct

# -----------------------------------------------------------------------
# 1. Générer une paire de clés et une signature de test
# -----------------------------------------------------------------------
msg = b"SuVa Protocol - ETHFalcon Phase 2"
print("[*] Génération des clés ETHFalcon-256...")

pk, sk = ETHFalcon256.keygen()
sig    = ETHFalcon256.sign(sk, msg)

# Vérifier côté Python avant de générer les test vectors
assert ETHFalcon256.verify(pk, msg, sig), "ERREUR : vérification Python échouée !"
print(f"[OK] Python verify réussi")
print(f"     Taille signature : {len(sig)} octets")

# Composants
h_coeffs = list(pk.h)                         # 256 coefficients Z_12289
nonce    = sig[1 : 1 + 40]                    # 40 octets
s_raw    = sig[1 + 40 :]                      # s2 compressé

# Décoder s2 pour l'exporter non compressé (format attendu par _decodeS2)
import falcon as falcon_lib
s2_signed = falcon_lib.decompress(s_raw, 256)
s2_bytes  = b"".join(
    struct.pack("<H", c % 12289) for c in s2_signed
)  # 256 × uint16 little-endian = 512 octets

# Signature pour le contrat : header(1) + nonce(40) + s2_raw(512)
sig_for_contract = sig[0:1] + nonce + s2_bytes

# -----------------------------------------------------------------------
# 2. Fonctions helper pour écrire du Solidity
# -----------------------------------------------------------------------

def sol_bytes(data: bytes, name: str) -> str:
    return f'bytes memory {name} = hex"{data.hex()}";\n'

def sol_uint256_arr(arr: list, name: str) -> str:
    lines = [f"uint256[256] memory {name};"]
    for i, v in enumerate(arr):
        lines.append(f"        {name}[{i}] = {v};")
    return "\n        ".join(lines) + "\n"

# -----------------------------------------------------------------------
# 3. Écrire le fichier .t.sol
# -----------------------------------------------------------------------
output_path = "../test/ZKNOX_ethfalcon.t.sol"

with open(output_path, "w") as f:
    f.write(
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.25;\n"
        "// Généré par generate_falcon_test_vectors.py — NE PAS MODIFIER MANUELLEMENT\n\n"
        'import {Test, console} from "forge-std/Test.sol";\n'
        'import {ZKNOX_ethfalcon} from "../src/ZKNOX_ethfalcon.sol";\n\n'
        "contract ETHFalconTest is Test {\n"
        "    ZKNOX_ethfalcon ethfalcon;\n\n"
        "    function setUp() public {\n"
        "        ethfalcon = new ZKNOX_ethfalcon();\n"
        "    }\n\n"
        "    // -------------------------------------------------------\n"
        "    // Test 1 : signature valide doit être acceptée\n"
        "    // -------------------------------------------------------\n"
        "    function testVerify() public {\n"
        "        "
    )
    f.write(sol_uint256_arr(h_coeffs, "h"))
    f.write(f"        {sol_bytes(msg, 'message')}")
    f.write(f"        {sol_bytes(sig_for_contract, 'signature')}")
    f.write(
        "\n        bool result = ethfalcon.verify(h, message, signature);\n"
        "        assertTrue(result, \"ETHFalcon verify doit retourner true\");\n"
        "    }\n\n"
        "    // -------------------------------------------------------\n"
        "    // Test 2 : mauvais message doit être rejeté\n"
        "    // -------------------------------------------------------\n"
        "    function testVerifyWrongMsg() public {\n"
        "        "
    )
    f.write(sol_uint256_arr(h_coeffs, "h"))
    f.write(f"        {sol_bytes(sig_for_contract, 'signature')}")
    f.write(
        "        bytes memory bad_msg = hex\"deadbeef\";\n"
        "        bool result = ethfalcon.verify(h, bad_msg, signature);\n"
        "        assertFalse(result, \"Mauvais message doit etre rejete\");\n"
        "    }\n"
        "}\n"
    )

print(f"[OK] Fichier généré : {output_path}")
```

---

## ÉTAPE 5 — Mesurer le gas

```bash
# 1. Générer les test vectors
cd python-ref/
python -m Falcon_dilithium_py.generate_falcon_test_vectors

# 2. Compiler et tester
cd ..
forge build

# 3. Lancer les tests avec rapport de gas
forge test --match-contract ETHFalconTest -vv --gas-report

# 4. Comparer avec ETHDilithium
forge test --match-contract "ETHDilithiumTest|ETHFalconTest" -vv --gas-report
```

**Résultat attendu :**

| Contrat | Fonction | Gas |
|---|---|---|
| ETHDilithiumTest | testVerify | ~6.58M |
| ETHFalconTest | testVerify | **à mesurer** |

---

## Résumé des commandes

```bash
# Installation
pip install falcon-py

# Tests Python (après étape 2)
python -m pytest Falcon_dilithium_py/tests/test_falcon.py -v

# Génération test vectors (après étape 3)
python -m Falcon_dilithium_py.generate_falcon_test_vectors

# Tests Solidity + gas (après étape 4)
forge test --match-contract ETHFalconTest -vv --gas-report
```

---

## Points d'attention

1. **`falcon_lib.decompress`** : l'API exacte de falcon-py peut varier.
   Si ça plante, cherche dans la lib : `help(falcon)` ou `dir(falcon)`.

2. **`_decodeS2` dans Solidity** : la version actuelle attend un encodage
   uint16 little-endian non compressé. Si falcon-py change le format, adapter.

3. **Gas élevé probable** : la multiplication schoolbook O(n²) coûte cher.
   Si le gas dépasse 6.58M, passer à NTT (Phase 2b).

4. **NTT Falcon** : q=12289, n=256. Constantes NTT différentes de Dilithium.
   Calculer avec : `pow(g, (q-1)//n, q)` avec g=11 (racine primitive mod 12289).
