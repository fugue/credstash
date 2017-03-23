from __future__ import absolute_import, division, print_function, unicode_literals


import six
from .aes_ctr import open_aes_ctr_legacy, seal_aes_ctr_legacy, ALGO_AES_CTR_LEGACY, \
    open_aes_ctr, seal_aes_ctr, ALGO_AES_CTR
from .aes_gcm import open_aes_gcm, seal_aes_gcm, ALGO_AES_GCM


def seal_secret(key_service, plaintext, metadata,
                algorithm=ALGO_AES_CTR, protocol=2, binary_type=None, **seal_kwargs):
    if isinstance(plaintext, six.text_type):
        plaintext = plaintext.encode('utf-8')

    if protocol == 1:
        additional_authenticated_data = {}
    elif protocol == 2:
        additional_authenticated_data = {
            'name': metadata['name'],
            'version': metadata['version'],
        }
    else:
        raise RuntimeError('Unsupported protocol: %s' % protocol)

    if not algorithm:
        algorithm = ALGO_AES_CTR

    if algorithm == ALGO_AES_GCM:
        ciphertext = seal_aes_gcm(
            key_service,
            plaintext,
            additional_authenticated_data,
            binary_type=binary_type,
            **seal_kwargs
        )
    elif algorithm == ALGO_AES_CTR:
        ciphertext = seal_aes_ctr(
            key_service,
            plaintext,
            additional_authenticated_data,
            binary_type=binary_type,
            **seal_kwargs
        )
    elif algorithm == ALGO_AES_CTR_LEGACY:
        ciphertext = seal_aes_ctr_legacy(
            key_service,
            plaintext,
            additional_authenticated_data,
            **seal_kwargs
        )
    else:
        raise RuntimeError('Unsupported algo: %s' % algorithm)

    ciphertext.update({
        'protocol': protocol,
    })
    return ciphertext


def open_secret(key_service, ciphertext, metadata):
    protocol = ciphertext.get('protocol', 1)
    if protocol == 1:
        additional_authenticated_data = {}
    elif protocol == 2:
        additional_authenticated_data = {
            'name': metadata['name'],
            'version': metadata['version'],
        }
    else:
        raise RuntimeError('Unsupported protocol: %s' % protocol)

    algorithm = ciphertext.get('algorithm')

    if algorithm == ALGO_AES_GCM:
        return open_aes_gcm(key_service, ciphertext, additional_authenticated_data)

    if algorithm == ALGO_AES_CTR:
        return open_aes_ctr(key_service, ciphertext, additional_authenticated_data)

    if not algorithm or algorithm == ALGO_AES_CTR_LEGACY:
        return open_aes_ctr_legacy(key_service, ciphertext, additional_authenticated_data)

    raise RuntimeError('Unsupported algo: %s' % algorithm)

