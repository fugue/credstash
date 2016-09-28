from __future__ import absolute_import, division, print_function, unicode_literals

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALGO_AES_GCM = 'aes-gcm'
DEFAULT_KEY_LENGTH = 32
DEFAULT_IV_LENGTH = 12


def open_aes_gcm(key_service, material):
    """
    Decrypts secrets stored by `seal_aes_ctr`.

    Allows for binary plaintext
    """
    key = key_service.decrypt(material['key'])
    return _open_aes_gcm(
        key,
        material['iv'],
        material['tag'],
        material['contents']
    )


def seal_aes_gcm(key_service, secret, key_length=DEFAULT_KEY_LENGTH, iv_length=DEFAULT_IV_LENGTH, binary_type=None):
    """
    Encrypts `secret` using the key service.

    You can decrypt with the companion method `open_aes_ctr`.
    """
    key, encoded_key = key_service.generate_key_data(key_length)
    iv, tag, ciphertext = _seal_aes_gcm(secret, key, iv_length)

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
        'iv': Binary(iv),
        'tag': Binary(tag),
        'algorithm': ALGO_AES_GCM,
    }


def _open_aes_gcm(key, iv, tag, ciphertext):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _seal_aes_gcm(plaintext, key, iv_length):
    iv = os.urandom(int(iv_length))
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, encryptor.tag, ciphertext
