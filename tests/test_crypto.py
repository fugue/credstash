from __future__ import absolute_import, division, print_function, unicode_literals

import os
import base64
import credsmash.crypto.aes_ctr as aes_ctr
import credsmash.crypto.aes_gcm as aes_gcm


class DummyKeyService(object):
    def generate_key_data(self, number_of_bytes):
        key = os.urandom(int(number_of_bytes))
        return key, base64.b64encode(key)

    def decrypt(self, encoded_key):
        return base64.b64decode(encoded_key)


def test_aes_ctr_legacy():
    """
    Basic test to ensure `cryptography` is installed/working
    """
    key_service = DummyKeyService()

    plaintext = b'abcdefghi'
    material = aes_ctr.seal_aes_ctr_legacy(
        key_service,
        plaintext
    )
    recovered_plaintext = aes_ctr.open_aes_ctr_legacy(
        key_service, material
    )
    assert plaintext == recovered_plaintext

    material = aes_ctr.seal_aes_ctr_legacy(
        key_service,
        plaintext,
        digest_method='SHA512'
    )
    recovered_plaintext = aes_ctr.open_aes_ctr_legacy(
        key_service, material
    )
    assert plaintext == recovered_plaintext


def test_aes_ctr():
    key_service = DummyKeyService()

    plaintext = b'abcdefghi'
    material = aes_ctr.seal_aes_ctr(
        key_service,
        plaintext
    )
    recovered_plaintext = aes_ctr.open_aes_ctr(
        key_service, material
    )
    assert plaintext == recovered_plaintext

    material = aes_ctr.seal_aes_ctr(
        key_service,
        plaintext,
        digest_method='SHA512'
    )
    recovered_plaintext = aes_ctr.open_aes_ctr(
        key_service, material
    )
    assert plaintext == recovered_plaintext


def test_aes_gcm():
    key_service = DummyKeyService()

    plaintext = b'abcdefghi'
    material = aes_gcm.seal_aes_gcm(
        key_service,
        plaintext
    )
    recovered_plaintext = aes_gcm.open_aes_gcm(
        key_service, material
    )
    assert plaintext == recovered_plaintext

