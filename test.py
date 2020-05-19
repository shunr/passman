import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import passman.accounts as accounts
from passman.key_utils import (
    derive_key_from_master_password_and_secret_key,
    generate_asymmetric_key_pair,
    generate_secret_key,
)

if __name__ == "__main__":
    username = input("Account id: ")
    password = input("Password: ")

    accounts.create_account(username, password)
    key = generate_secret_key(username)[:32]
    print(key)
    print(generate_asymmetric_key_pair())

    data = "HELLO!!!".encode()
    aesgcm = AESGCM(key.encode())
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    x = aesgcm.decrypt(nonce, ct, None)
    print(x)
