#!/usr/bin/env python

"""
test_x25519hkdf
---------------

Tests for the `x25519hkdf` module which implements the core functionality
of XSTREAM
"""

import unittest

from xstream import (Encryptor, Decryptor)

from .support.test_vectors import XStreamExample


class TestEncryptor(unittest.TestCase):
    def test_seal(self):
        """Ensure seal passes all XSTREAM test vectors"""
        for ex in XStreamExample.load():
            if ex.alg == u'XSTREAM_X25519_HKDF_SHA256_AES128_SIV':
                encryption_alg = "AES-SIV"
            elif ex.alg == u'XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV':
                encryption_alg = "AES-PMAC-SIV"
            else:
                raise RuntimeError("unknown encryption algorithm: " + ex.alg)

            encryptor, _ephemeral = Encryptor.generate(
                public_key=ex.sealingkey.pubkey,
                encryption_alg=encryption_alg,
                salt=ex.salt,
                csrng=lambda _n: ex.ephemeralkey.seckey
            )

            for i, block in enumerate(ex.blocks):
                ciphertext = encryptor.seal(block.plaintext, associated_data=block.ad, last_block=i+1 == len(ex.blocks))
                self.assertEqual(ciphertext, block.ciphertext)


class TestDecryptor(unittest.TestCase):
    def test_open(self):
        """Ensure open passes all XSTREAMtest vectors"""
        for ex in XStreamExample.load():
            if ex.alg == u'XSTREAM_X25519_HKDF_SHA256_AES128_SIV':
                encryption_alg = "AES-SIV"
            elif ex.alg == u'XSTREAM_X25519_HKDF_SHA256_AES128_PMAC_SIV':
                encryption_alg = "AES-PMAC-SIV"
            else:
                raise RuntimeError("unknown encryption algorithm: " + ex.alg)

            decryptor = Decryptor(
                private_key=ex.sealingkey.seckey,
                ephemeral_public=ex.ephemeralkey.pubkey,
                encryption_alg=encryption_alg,
                salt=ex.salt
            )

            for i, block in enumerate(ex.blocks):
                plaintext = decryptor.open(block.ciphertext, associated_data=block.ad, last_block=i+1 == len(ex.blocks))
                self.assertEqual(plaintext, block.plaintext)
