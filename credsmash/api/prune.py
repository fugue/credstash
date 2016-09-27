from __future__ import absolute_import, division, print_function, unicode_literals

import logging
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger(__name__)


def prune_secret(secrets_table, secret_name):
    response = secrets_table.scan(
        FilterExpression=Attr("name").eq(secret_name),
        ProjectionExpression="#N, version",
        ExpressionAttributeNames={"#N": "name"}
    )
    if response['Count'] == 0:
        logger.info('Not found: %s', secret_name)
        return

    max_version = max(
        int(secret['version'])
        for secret in response['Items']
    )

    for secret in response["Items"]:
        if int(secret['version']) == max_version:
            continue
        logger.info("Deleting %s -- version %s",
                    secret["name"], secret["version"])
        secrets_table.delete_item(Key=secret)
    logger.info('Pruned %s (current version=%d)', secret_name, max_version)
