"""x25519hkdf.py: Implementation of XSTREAM's core cryptographic primitive combining X25519+HKDF+STREAM"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from miscreant import stream

# Domain separation string passed as HKDF info
HKDF_INFO = b"XSTREAM_X25519_HKDF"

# Size of an X25519 key
X25519_KEY_SIZE = 32

# Size of an AES-128 key * 2 (for SIV mode)
SYMMETRIC_KEY_SIZE = 32

# STREAM nonce of all zeroes (since we always derive a unique key per STREAM)
NONCE = b"\0\0\0\0\0\0\0\0"


class Encryptor(stream.Encryptor):
    """XSTREAM encryptor with X25519+HKDF key derivation"""

    @staticmethod
    def generate(
        public_key,
        encryption_alg="AES-PMAC-SIV",
        digest_alg=hashes.SHA256(),
        salt=None,
        csrng=os.urandom,
    ):
        """
        Generate an XSTREAM encryptor object with a random ephemeral key

        :param public_key: 32-byte X25519 public key (i.e. compressed Montgomery-u coordinate)
        :param encryption_alg: symmetric encryption algorithm to use with STREAM (default "AES-PMAC-SIV")
        :param digest_alg: digest algorithm to use with HKDF (default "SHA256")
        :param salt: (optional) salt value to pass to HKDF (default None)
        :param csrng: (optional) secure random number generator used to generate ephemeral key (default os.urandom)
        :return: STREAM encryptor and ephemeral public key
        """
        ephemeral_scalar = X25519PrivateKey._from_private_bytes(csrng(X25519_KEY_SIZE))

        symmetric_key = kdf(
          private_key=ephemeral_scalar,
          public_key=X25519PublicKey.from_public_bytes(public_key),
          digest_alg=digest_alg,
          length=SYMMETRIC_KEY_SIZE,
          salt=salt
        )

        enc = Encryptor(encryption_alg, symmetric_key, NONCE)
        return enc, ephemeral_scalar.public_key().public_bytes()


class Decryptor(stream.Decryptor):
    """XSTREAM decryptor class with X25519+HKDF key derivation"""

    def __init__(
        self,
        private_key,
        ephemeral_public,
        encryption_alg="AES-PMAC-SIV",
        digest_alg=hashes.SHA256(),
        salt=None
    ):
        """
        Create an XSTREAM decryptor object using our private key and an ephemeral public key

        :param private_key: 32-byte X25519 private key (i.e. private scalar)
        :param ephemeral_public: 32-byte X25519 ephemeral public key from XSTREAM encryption
        :param encryption_alg: symmetric encryption algorithm to use with STREAM (default "AES-PMAC-SIV")
        :param digest_alg: digest algorithm to use with HKDF (default "SHA256")
        :param salt: (optional) salt value to pass to HKDF (default None)
        """

        # Perform an X25519 elliptic curve Diffie-Hellman operation and use
        # the resulting shared secret to derive a symmetric key (using HKDF)
        symmetric_key = kdf(
          private_key=X25519PrivateKey._from_private_bytes(private_key),
          public_key=X25519PublicKey.from_public_bytes(ephemeral_public),
          digest_alg=digest_alg,
          length=SYMMETRIC_KEY_SIZE,
          salt=salt
        )

        super(Decryptor, self).__init__(encryption_alg, symmetric_key, NONCE)


def kdf(
    private_key,
    public_key,
    length,
    salt=None,
    digest_alg=hashes.SHA256(),
    backend=default_backend()
):
    """
    Derive a symmetric encryption key from the combination of a public and
    private key and salt using X25519 D-H and HKDF
    """
    # Use HKDF to derive a symmetric encryption key from the shared secret
    hkdf = HKDF(
        algorithm=digest_alg,
        length=length,
        salt=salt,
        info=HKDF_INFO,
        backend=backend
    )

    # Use X25519 to compute a shared secret
    return hkdf.derive(private_key.exchange(public_key))
