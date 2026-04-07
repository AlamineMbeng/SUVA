"""
Paramètres Falcon — SuVa Phase 2.
q = 12289 (différent de Dilithium q = 8380417)
On cible Falcon-256 (n=256) pour minimiser le gas on-chain.

Valeurs vérifiées avec falcon_sign.py :
  Falcon(256).param.sig_bound   = 16468416
  Falcon(256).param.sig_bytelen = 356
  Falcon(256).param.n           = 256
  vk length                     = 448 bytes (224 coefficients × 2B)
"""

FALCON_256 = {
    "n": 256,
    "q": 12289,
    "sig_bound": 16468416,  # ||s0||^2 + ||s1||^2 <= sig_bound
    "nonce_len": 40,        # SALT_LEN dans falcon_sign.py
    "sig_bytelen": 356,     # longueur totale signature (header+salt+enc_s)
    "vk_bytelen": 448,      # longueur clé publique sérialisée
}

FALCON_512 = {
    "n": 512,
    "q": 12289,
    "sig_bound": 34034726,
    "nonce_len": 40,
    "sig_bytelen": 666,
    "vk_bytelen": 897,
}

Q = 12289
