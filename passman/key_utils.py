import os
from unicodedata import normalize

from authlib.jose import jwk

from passman.crypto.asymmetric import PublicKeyAlgorithm, generate_key_pair
from passman.crypto.key_derivation import hkdf, pbkdf2

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION_INFO = "00"
KEY_LENGTH = 32


def generate_secret_key(user_id: str, key_length: int = 26) -> str:
    unambiguous_32_alphanumeric = list("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
    random_bytes = list(os.urandom(key_length))

    # TODO: Comment on uniformness of taking a random byte value modulo 32
    random_chars = [unambiguous_32_alphanumeric[b % 32] for b in random_bytes]

    return (VERSION_INFO + user_id[:6] + "".join(random_chars)).upper()


def generate_asymmetric_key_pair():
    key_pair = generate_key_pair(algorithm=PublicKeyAlgorithm.EC_SECP384R1)

    return (jwk.dumps(key_pair.private_key, kty="EC", kid="priv"), jwk.dumps(key_pair.public_key, kty="EC", kid="yuh"))


def bxor(b1: bytes, b2: bytes) -> bytes:
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)


def derive_key_from_master_password_and_secret_key(
    user_id: str, user_email: str, master_password: str, secret_key: str, salt: bytes
) -> bytes:

    password_normalized = normalize("NFKD", master_password.strip()).encode()

    master_key_salt = hkdf(salt, salt=user_email.encode(), info=VERSION_INFO.encode())
    master_key_derived = pbkdf2(password_normalized, salt=master_key_salt)
    secret_key_derived = hkdf(
        secret_key.encode(), salt=user_id.encode(), info=VERSION_INFO.encode()
    )

    derived_key = bxor(master_key_derived, secret_key_derived)
    return derived_key
    return jwk.dumps(
        derived_key,
        alg="A256GCM",
        ext=False,
        key_ops=["encrypt", "decrypt"],
        kty="oct",
        kid="mp",
    )


if __name__ == "__main__":
    user_id = input("User id:")
    email = input("Email:")
    password = input("Password:")
    secret_key = "00ABCDE1N9ZD4LT7VZZS52SJFC6ZP49XHE"
    user_salt = "abcd".encode()

    key = derive_key_from_master_password_and_secret_key(
        user_id=user_id,
        user_email=email,
        master_password=password,
        secret_key=secret_key,
        salt=user_salt,
    )

    print(generate_asymmetric_key_pair())

    data = "HELLO!!!".encode()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    x = aesgcm.decrypt(nonce, ct, None)
    print(x)