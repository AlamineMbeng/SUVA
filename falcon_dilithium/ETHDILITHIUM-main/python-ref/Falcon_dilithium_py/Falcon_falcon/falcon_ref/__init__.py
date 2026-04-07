"""
Wrapper autour du code source Falcon de Thomas Prest (tprest/falcon.py).

Les fichiers de ce dossier utilisent des imports "flat" (sans package),
donc on patche sys.path pour qu'ils se trouvent mutuellement.
"""
import sys
import os

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from .falcon_sign import Falcon  # noqa: E402

Falcon256 = Falcon(256)
Falcon512 = Falcon(512)
