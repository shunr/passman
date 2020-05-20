import os
import uuid

import requests
import srp
from authlib.jose import jwk

import passman.key_utils as key_utils


class CreateAccountError(Exception):
    pass


def create_account(username: str, password: str):
    secret_key = key_utils.generate_secret_key(username)
    master_unlock_salt = key_utils.generate_salt()
    authentication_salt = key_utils.generate_salt()

    # Generate key to decrypt
    master_unlock_key = key_utils.derive_key_from_master_password_and_secret_key(
        username=username,
        master_password=password,
        secret_key=secret_key,
        salt=master_unlock_salt,
    )

    # Generate x for SRP
    srp_x = key_utils.derive_key_from_master_password_and_secret_key(
        username=username,
        master_password=password,
        secret_key=secret_key,
        salt=authentication_salt,
    )

    # Create account's keypair
    key_id = uuid.uuid1()
    key_pair = key_utils.generate_asymmetric_key_pair()
    # TODO: design flexible way to specify kty, if switching between EC and RSA, for example

    print(
        jwk.dumps(key_pair.private_key, kty="RSA", kid="priv"),
        jwk.dumps(key_pair.public_key, kty="RSA"),
    )

    from passman.srp_example import create_v

    verifier = create_v(srp_x)

    # Attempt to create an account
    url = "http://localhost:443/create_account"
    data = {
        "username": username,
        "display_name": "Person",
        "auth_salt_hex": authentication_salt.hex(),
        "muk_salt_hex": master_unlock_salt.hex(),
        "auth_verifier_hex": verifier.hex(),
    }
    x = requests.post(url, json=data)

    print(x.text)
