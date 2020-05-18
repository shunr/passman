from enum import Enum
from typing import Callable, Tuple
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aesgcm_encrypt(data: bytes, key: bytes):
    nonce = os.urandom(16)
    aesgcm = AESGCM(key)
    return (aesgcm.encrypt(nonce, data, None), nonce)


def aesgcm_decrypt(data: bytes, key: bytes, nonce: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, None)
