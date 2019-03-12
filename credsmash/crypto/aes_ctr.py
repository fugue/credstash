from __future__ import absolute_import, division, print_function, unicode_literals

import os
import base64
import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

ALGO_AES_CTR = 'aes-ctr'
ALGO_AES_CTR_LEGACY = 'aes-ctr-legacy'


DEFAULT_KEY_LENGTH = 64

_hash_classes = {
    'SHA224': hashes.SHA224,
    'SHA256': hashes.SHA256,
    'SHA384': hashes.SHA384,
    'SHA512': hashes.SHA512,
}

DEFAULT_DIGEST = 'SHA256'
HASHING_ALGORITHMS = list(_hash_classes.keys())
LEGACY_NONCE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def open_aes_ctr(key_service, material):
    """
    Decrypts secrets stored by `seal_aes_ctr`.

    Allows for binary plaintext
    """
    key = key_service.decrypt(material['key'])
    digest_method = material.get('digest', DEFAULT_DIGEST)
    ciphertext = material['contents']
    hmac = material['hmac']
    nonce = material.get('nonce', LEGACY_NONCE)
    return _open_aes_ctr(key, nonce, ciphertext, hmac, digest_method)


def seal_aes_ctr(key_service, secret, digest_method=DEFAULT_DIGEST, key_length=DEFAULT_KEY_LENGTH, binary_type=None):
    """
    Encrypts `secret` using the key service.

    You can decrypt with the companion method `open_aes_ctr`.
    """
    key, encoded_key = key_service.generate_key_data(key_length)
    nonce = os.urandom(16)
    ciphertext, hmac = _seal_aes_ctr(
        secret, key, nonce, digest_method
    )

    # Agh! a mighty break in abstraction
    # DynamoDB wont put `bytes` => `Binary` in python2
    # So we need to wrap it with a special type
    def Binary(value):
        if binary_type:
            return binary_type(value)
        return value
    return {
        'key': Binary(encoded_key),
        'contents': Binary(ciphertext),
        'hmac': Binary(hmac),
        'nonce': Binary(nonce),
        'digest': digest_method,
        'algorithm': ALGO_AES_CTR,
    }


def open_aes_ctr_legacy(key_service, material):
    """
    Decrypts secrets stored by `seal_aes_ctr_legacy`.

    Assumes that the plaintext is str (non-binary).
    """
    key = key_service.decrypt(_from_b64(material['key']))
    digest_method = material.get('digest', DEFAULT_DIGEST)
    ciphertext = _from_b64(material['contents'])
    hmac = _from_hex(material['hmac'])
    return _open_aes_ctr(key, LEGACY_NONCE, ciphertext, hmac, digest_method)


def seal_aes_ctr_legacy(key_service, secret, digest_method=DEFAULT_DIGEST):
    """
    :deprecated: Please use `seal_aes_ctr` instead.

    Encrypts `secret` using the key service.

    You can decrypt with the companion method `open_aes_ctr_legacy`.
    """
    # generate a a 64 byte key.
    # Half will be for data encryption, the other half for HMAC
    key, encoded_key = key_service.generate_key_data(64)
    ciphertext, hmac = _seal_aes_ctr(
        secret, key, LEGACY_NONCE, digest_method,
    )
    return {
        'key': _to_b64(encoded_key),
        'contents': _to_b64(ciphertext),
        'hmac': _to_hex(hmac),
        'digest': digest_method,
    }


def _open_aes_ctr(key, nonce, ciphertext, expected_hmac, digest_method):
    data_key, hmac_key = _halve_key(key)
    hmac = _get_hmac(hmac_key, ciphertext, digest_method)
    # Check the HMAC before we decrypt to verify ciphertext integrity
    if hmac != expected_hmac:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC")

    decryptor = Cipher(
        algorithms.AES(data_key),
        modes.CTR(nonce),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _seal_aes_ctr(plaintext, key, nonce, digest_method):
    data_key, hmac_key = _halve_key(key)
    encryptor = Cipher(
        algorithms.AES(data_key),
        modes.CTR(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, _get_hmac(hmac_key, ciphertext, digest_method)


def _get_hmac(key, ciphertext, digest_method):
    hmac = HMAC(
        key,
        get_digest(digest_method),
        backend=default_backend()
    )
    hmac.update(ciphertext)
    return hmac.finalize()


def _halve_key(key):
    half = len(key) // 2
    return key[:half], key[half:]


def get_digest(digest):
    try:
        return _hash_classes[digest]()
    except KeyError:
        raise ValueError("Could not find " + digest + " in cryptography.hazmat.primitives.hashes")


def _to_hex(b):  # type (bytes): -> str
    return binascii.hexlify(b).decode('ascii')


def _from_hex(s):  # type: (str) -> bytes
    return binascii.unhexlify(s)


def _to_b64(b):  # type (bytes): -> str
    b2 = base64.b64encode(b)
    return b2.decode('ascii')


def _from_b64(s):  # type (str): -> bytes
    b = s.encode('ascii')
    return base64.b64decode(b)


class IntegrityError(Exception):

    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else \
                     "INTEGRITY ERROR"

    def __str__(self):
        return self.value
