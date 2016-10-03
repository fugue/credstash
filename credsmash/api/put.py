from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from credsmash.crypto import seal_secret, open_secret, ALGO_AES_CTR

logger = logging.getLogger(__name__)


def put_secret(
        storage_service, key_service, secret_name,
        plaintext, version=None, compare=True,
        algorithm=ALGO_AES_CTR, **seal_kwargs
):
    sealed = seal_secret(
        key_service,
        plaintext,
        algorithm=algorithm,
        binary_type=storage_service.binary_type,
        **seal_kwargs
    )

    if version is None:
        latest_secret = storage_service.get_one(secret_name)
        version = 1
        if latest_secret:
            version += latest_secret['version']
            if compare:
                latest_plaintext = open_secret(key_service, latest_secret)
                if plaintext == latest_plaintext:
                    logger.debug('secret "%s" is unchanged', secret_name)
                    return latest_secret['version']

    storage_service.put_one(secret_name, version, sealed)
    return version
