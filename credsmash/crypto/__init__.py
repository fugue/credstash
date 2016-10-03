from __future__ import absolute_import, division, print_function, unicode_literals


import six
from .aes_ctr import open_aes_ctr_legacy, seal_aes_ctr_legacy, ALGO_AES_CTR_LEGACY, \
    open_aes_ctr, seal_aes_ctr, ALGO_AES_CTR
from .aes_gcm import open_aes_gcm, seal_aes_gcm, ALGO_AES_GCM


def seal_secret(key_service, plaintext, algorithm=ALGO_AES_CTR, binary_type=None, **seal_kwargs):
    if isinstance(plaintext, six.text_type):
        plaintext = plaintext.encode('utf-8')

    if not algorithm:
        algorithm = ALGO_AES_CTR

    if algorithm == ALGO_AES_GCM:
        return seal_aes_gcm(
            key_service,
            plaintext,
            binary_type=binary_type,
            **seal_kwargs
        )
    if algorithm == ALGO_AES_CTR:
        return seal_aes_ctr(
            key_service,
            plaintext,
            binary_type=binary_type,
            **seal_kwargs
        )
    if algorithm == ALGO_AES_CTR_LEGACY:
        return seal_aes_ctr_legacy(
            key_service,
            plaintext,
            **seal_kwargs
        )
    raise RuntimeError('Unsupported algo: %s' % algorithm)


def open_secret(key_service, ciphertext):
    algorithm = ciphertext.get('algorithm')

    if algorithm == ALGO_AES_GCM:
        return open_aes_gcm(key_service, ciphertext)

    if algorithm == ALGO_AES_CTR:
        return open_aes_ctr(key_service, ciphertext)

    if not algorithm or algorithm == ALGO_AES_CTR_LEGACY:
        return open_aes_ctr_legacy(key_service, ciphertext)

    raise RuntimeError('Unsupported algo: %s' % algorithm)

