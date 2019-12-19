from enum import Enum
from typing import Callable, cast, Dict, Optional, Tuple

import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

DEFAULT_BACKEND = default_backend()


class PublicKeyAlgorithm(Enum):
    RSA_4096 = "rsa_4096"
    RSA_3072 = "rsa_3072"
    EC_SECP384R1 = "ec_secp384r1"


class KeyPair:
    def __init__(
        self, private_bytes: bytes, public_bytes: bytes, key_type: PublicKeyAlgorithm
    ):
        self.private_key = private_bytes
        self.public_key = public_bytes
        self.key_type = key_type


KeyPairGenerator = Callable[[], KeyPair]


class _PublicKeyAlgorithmImpl:
    mapping: Dict[PublicKeyAlgorithm, KeyPairGenerator] = {}

    def __init__(self, algorithm: PublicKeyAlgorithm):
        self.algorithm = algorithm

    def __call__(self, function: KeyPairGenerator) -> KeyPairGenerator:
        self.mapping[self.algorithm] = function
        return function

    @classmethod
    def get(cls, algorithm: PublicKeyAlgorithm) -> Optional[KeyPairGenerator]:
        return cls.mapping.get(algorithm)


@_PublicKeyAlgorithmImpl(PublicKeyAlgorithm.RSA_4096)
def _rsa_4096() -> KeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=DEFAULT_BACKEND
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(pem, pem_pub, key_type=PublicKeyAlgorithm.RSA_4096)


@_PublicKeyAlgorithmImpl(PublicKeyAlgorithm.RSA_3072)
def _rsa_3072() -> KeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=3072, backend=DEFAULT_BACKEND
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(pem, pem_pub, key_type=PublicKeyAlgorithm.RSA_3072)


@_PublicKeyAlgorithmImpl(PublicKeyAlgorithm.EC_SECP384R1)
def _ec_SECP384R1() -> KeyPair:
    private_key = ec.generate_private_key(
        curve=cast(ec.EllipticCurve, ec.SECP384R1), backend=DEFAULT_BACKEND
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(  # type: ignore
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return KeyPair(pem, pem_pub, key_type=PublicKeyAlgorithm.EC_SECP384R1)


def generate_key_pair(algorithm: PublicKeyAlgorithm) -> KeyPair:
    function = _PublicKeyAlgorithmImpl.get(algorithm)
    if not function:
        raise KeyError(
            "Private key cryptography using {} is not implemented!".format(algorithm)
        )
    return function()
