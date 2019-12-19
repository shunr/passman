from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_BACKEND = default_backend()

KEY_LENGTH = 32


def hkdf(key_material: bytes, salt: bytes, info: Optional[bytes] = None) -> bytes:
    key_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=info,
        backend=DEFAULT_BACKEND,
    ).derive(key_material)
    return key_bytes


def pbkdf2(key_material: bytes, salt: bytes) -> bytes:
    key_bytes = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=100000,
        backend=DEFAULT_BACKEND,
    ).derive(key_material)
    return key_bytes
