"""test_vectors.py: Parse examples from vectors/xstream.tjson"""

import binascii
import json
from collections import namedtuple

class XStreamKeypair(namedtuple("XStreamKeypair", [
    "pubkey",
    "seckey"
])):
    """X25519 keypair"""
    pass

class XStreamBlock(namedtuple("XStreamBlock", [
    "ad",
    "plaintext",
    "ciphertext"
])):
    """STREAM block with key derived via XSTREAM KDF"""
    pass

class XStreamExample(namedtuple("XStreamExample", [
    "name",
    "alg",
    "sealingkey",
    "ephemeralkey",
    "salt",
    "blocks"
])):
    """XSTREAM test vector"""

    @staticmethod
    def load():
        """Load message examples from vectors/xstream.tjson"""
        return XStreamExample.load_from_file("../vectors/xstream.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            if u"salt:d16" in example:
                salt = binascii.unhexlify(example[u"salt:d16"])
            else:
                salt = None

            blocks = []
            for b in example[u"blocks:A<O>"]:
                blocks.append(XStreamBlock(
                    ad=binascii.unhexlify(b["ad:d16"]),
                    plaintext=binascii.unhexlify(b["plaintext:d16"]),
                    ciphertext=binascii.unhexlify(b["ciphertext:d16"])
                ))

            result.append(XStreamExample(
                name=example[u"name:s"],
                alg=example[u"alg:s"],
                sealingkey=XStreamKeypair(
                    pubkey=binascii.unhexlify(example[u"sealingkey:O"][u"pubkey:d16"]),
                    seckey=binascii.unhexlify(example[u"sealingkey:O"][u"seckey:d16"]),
                ),
                ephemeralkey=XStreamKeypair(
                    pubkey=binascii.unhexlify(example[u"ephemeralkey:O"][u"pubkey:d16"]),
                    seckey=binascii.unhexlify(example[u"ephemeralkey:O"][u"seckey:d16"]),
                ),
                salt=salt,
                blocks=blocks
            ))

        return result
