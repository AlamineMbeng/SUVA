"""
Opérations polynomiales dans Z_q[X]/(X^n + 1) pour Falcon.
q = 12289, n = 256.

Règle clé : X^n ≡ -1  →  X^(n+k) ≡ -X^k
→ Lors d'une multiplication, si i+j >= n, le signe s'inverse.

Ces fonctions reproduisent mul_zq et sub_zq de ntt.py (falcon_ref).
"""

Q = 12289


def poly_mul(a: list, b: list, q: int = Q) -> list:
    """
    Multiplication dans Z_q[X]/(X^n + 1) — schoolbook O(n²).
    Même résultat que mul_zq(a, b) de ntt.py.
    """
    n = len(a)
    result = [0] * n
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            prod = (a[i] * b[j]) % q
            if i + j >= n:
                result[idx] = (result[idx] - prod) % q
            else:
                result[idx] = (result[idx] + prod) % q
    return result


def poly_sub(a: list, b: list, q: int = Q) -> list:
    """Soustraction coefficient par coefficient mod q."""
    return [(x - y) % q for x, y in zip(a, b)]


def norm_sq(s: list, q: int = Q) -> int:
    """
    Norme L2 au carré — coefficients centrés dans (-q/2, q/2].
    Si c > q/2 : c représente c - q (valeur négative).
    """
    half_q = q >> 1
    total = 0
    for c in s:
        if c > half_q:
            c = c - q
        total += c * c
    return total
