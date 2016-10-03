from __future__ import absolute_import, division, print_function, unicode_literals

import logging

logger = logging.getLogger(__name__)


def prune_secret(storage_service, secret_name):
    secrets = storage_service.list_one(secret_name)
    if not secrets:
        logger.info('Not found: %s', secret_name)
        return

    max_version = max(
        secret['version']
        for secret in secrets
    )

    for secret in secrets:
        if secret['version'] == max_version:
            continue
        logger.info("Deleting %s -- version %s",
                    secret["name"], secret["version"])
        storage_service.delete_one(
            secret['name'], secret['version']
        )
    logger.info('Pruned %s (current version=%d)', secret_name, max_version)
