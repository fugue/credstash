from __future__ import absolute_import, division, print_function, unicode_literals

import importlib
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter


DEFAULT_DIGEST = 'SHA256'
HASHING_ALGORITHMS = ['SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
                      'MD2', 'MD4', 'MD5', 'RIPEMD']


def open_aes_ctr_legacy(key_service, material):
    """
    Decrypts secrets stored by `seal_aes_ctr_legacy`.

    Assumes that the plaintext is unicode (non-binary).
    """
    key = key_service.decrypt(b64decode(material['key']))
    digest_method = material.get('digest', DEFAULT_DIGEST)
    ciphertext = b64decode(material['contents'])
    hmac = material['hmac'].decode('hex')
    return _open_aes_ctr(key, ciphertext, hmac, digest_method).decode("utf-8")


def seal_aes_ctr_legacy(key_service, secret, digest_method=DEFAULT_DIGEST):
    """
    Encrypts `secret` using the key service.

    You can decrypt with the companion method `open_aes_ctr_legacy`.
    """
    # generate a a 64 byte key.
    # Half will be for data encryption, the other half for HMAC
    key, encoded_key = key_service.generate_key_data(64)
    ciphertext, hmac = _seal_aes_ctr(
        secret, key, digest_method
    )
    return {
        'key': b64encode(encoded_key).decode('utf-8'),
        'contents': b64encode(ciphertext).decode('utf-8'),
        'hmac': hmac.encode('hex'),
        'digest_method': digest_method,
    }


def _open_aes_ctr(key, ciphertext, expected_hmac, digest_method):
    data_key, hmac_key = _halve_key(key)
    hmac = HMAC(hmac_key, msg=ciphertext,
                digestmod=get_digest(digest_method))
    # Check the HMAC before we decrypt to verify ciphertext integrity
    if hmac.digest() != expected_hmac:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC")
    dec_ctr = Counter.new(128)
    decryptor = AES.new(data_key, AES.MODE_CTR, counter=dec_ctr)
    return decryptor.decrypt(ciphertext)


def _seal_aes_ctr(secret, key, digest_method):
    data_key, hmac_key = _halve_key(key)
    enc_ctr = Counter.new(128)
    encryptor = AES.new(data_key, AES.MODE_CTR, counter=enc_ctr)
    ciphertext = encryptor.encrypt(secret)
    hmac = HMAC(hmac_key, msg=ciphertext, digestmod=get_digest(digest_method))
    return ciphertext, hmac.digest()


def _halve_key(key):
    half = len(key) // 2
    return key[:half], key[half:]


def get_digest(digest):
    try:
        return importlib.import_module('Crypto.Hash.{0}'.format(digest))
    except ImportError:
        raise ValueError("Could not find " + digest + " in Crypto.Hash")


class IntegrityError(Exception):

    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else \
                     "INTEGRITY ERROR"

    def __str__(self):
        return self.value
