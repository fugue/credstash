from __future__ import absolute_import, division, print_function, unicode_literals

import base64
import json
import os

import credsmash.crypto.aes_ctr as aes_ctr
import credsmash.crypto.aes_gcm as aes_gcm


class DummyKeyService(object):
    def generate_key_data(self, number_of_bytes, additional_authenticated_data=None):
        key = os.urandom(int(number_of_bytes))
        return key, json.dumps({"key": base64.b64encode(key), "aad": additional_authenticated_data})

    def decrypt(self, encoded_key, additional_authenticated_data=None):
        key_data = json.loads(encoded_key)
        if additional_authenticated_data != key_data['aad']:
            raise RuntimeError('Mismatch additional_authenticated_data')
        return base64.b64decode(key_data['key'])


def test_aes_ctr_legacy():
    """
    Basic test to ensure `cryptography` is installed/working
    """
    key_service = DummyKeyService()

    plaintext = b'abcdefghi'
    material = aes_ctr.seal_aes_ctr_legacy(
        key_service,
        plaintext, {}
    )
    recovered_plaintext = aes_ctr.open_aes_ctr_legacy(
        key_service, material, {}
    )
    assert plaintext == recovered_plaintext

    material = aes_ctr.seal_aes_ctr_legacy(
        key_service,
        plaintext,
        {},
        digest_method='SHA512'
    )
    recovered_plaintext = aes_ctr.open_aes_ctr_legacy(
        key_service, material, {}
    )
    assert plaintext == recovered_plaintext


def test_aes_ctr():
    key_service = DummyKeyService()

    plaintext = b'abcdefghi'
    material = aes_ctr.seal_aes_ctr(
        key_service,
        plaintext, {}
    )
    recovered_plaintext = aes_ctr.open_aes_ctr(
        key_service, material, {}
    )
    assert plaintext == recovered_plaintext

    material = aes_ctr.seal_aes_ctr(
        key_service,
        plaintext,
        {},
        digest_method='SHA512'
    )
    recovered_plaintext = aes_ctr.open_aes_ctr(
        key_service, material, {}
    )
    assert plaintext == recovered_plaintext


def test_aes_gcm():
    key_service = DummyKeyService()

    plaintext = b'abcdefghi'
    material = aes_gcm.seal_aes_gcm(
        key_service,
        plaintext,
        {}
    )
    recovered_plaintext = aes_gcm.open_aes_gcm(
        key_service, material, {}
    )
    assert plaintext == recovered_plaintext

