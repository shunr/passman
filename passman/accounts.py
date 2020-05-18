import os
import uuid
import srp

import passman.key_utils as key_utils
from authlib.jose import jwk


class CreateAccountError(Exception):
    pass


def create_account(account_id: str, password: str):
    secret_key = key_utils.generate_secret_key(account_id)
    master_unlock_salt = key_utils.generate_salt()
    srp_x_salt = key_utils.generate_salt()

    # Generate key to decrypt
    master_unlock_key = key_utils.derive_key_from_master_password_and_secret_key(
        account_id=account_id,
        master_password=password,
        secret_key=secret_key,
        salt=master_unlock_salt,
    )

    # Generate x for SRP
    srp_x = key_utils.derive_key_from_master_password_and_secret_key(
        account_id=account_id,
        master_password=password,
        secret_key=secret_key,
        salt=srp_x_salt,
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
    print("V: ", create_v(srp_x))

    # Attempt to negotiate w/ server using SRP
