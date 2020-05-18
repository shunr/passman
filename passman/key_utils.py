import os
from unicodedata import normalize

from passman.crypto.asymmetric import PublicKeyAlgorithm, generate_key_pair, KeyPair
from passman.crypto.key_derivation import hkdf, scrypt_kdf

VERSION_INFO = "00"


def generate_salt(length: int = 32) -> bytes:
    """Generates a random salt of given length
    """
    return os.urandom(length)


def generate_secret_key(account_id: str, key_length: int = 26) -> str:
    # Exactly 32 unambiguous alphanumeric characters
    unambiguous_32_alphanumeric = list("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
    random_bytes = list(os.urandom(key_length))

    # Taking a value mod 32 from a uniform ditribution [0, 255] is uniform
    random_chars = [unambiguous_32_alphanumeric[b % 32] for b in random_bytes]

    return (VERSION_INFO + account_id.ljust(6, "X")[:6] + "".join(random_chars)).upper()


def generate_asymmetric_key_pair() -> KeyPair:
    key_pair = generate_key_pair(algorithm=PublicKeyAlgorithm.RSA_3072)
    return key_pair


def bxor(b1: bytes, b2: bytes) -> bytes:
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)


def derive_key_from_master_password_and_secret_key(
    account_id: str, master_password: str, secret_key: str, salt: bytes
) -> bytes:

    password_normalized = normalize("NFKD", master_password.strip()).encode()

    master_key_salt = hkdf(salt, salt=account_id.encode(), info=VERSION_INFO.encode())
    master_key_derived = scrypt_kdf(password_normalized, salt=master_key_salt)
    secret_key_derived = hkdf(
        secret_key.encode(), salt=account_id.encode(), info=VERSION_INFO.encode()
    )

    derived_key = bxor(master_key_derived, secret_key_derived)

    return derived_key
