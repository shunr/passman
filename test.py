import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import passman.accounts as accounts
from passman.key_utils import (
    derive_key_from_master_password_and_secret_key,
    generate_asymmetric_key_pair,
    generate_secret_key,
)

if __name__ == "__main__":
    account_id = input("Account id: ")
    password = input("Password: ")

    accounts.create_account(account_id, password)
    key = generate_secret_key(account_id)[:32]
    print(key)
    print(generate_asymmetric_key_pair())

    data = "HELLO!!!".encode()
    aesgcm = AESGCM(key.encode())
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    x = aesgcm.decrypt(nonce, ct, None)
    print(x)
