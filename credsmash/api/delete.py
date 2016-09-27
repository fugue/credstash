from __future__ import absolute_import, division, print_function, unicode_literals

import logging
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger(__name__)


def delete_secret(secrets_table, secret_name):
    response = secrets_table.scan(
        FilterExpression=Attr("name").eq(secret_name),
        ProjectionExpression="#N, version",
        ExpressionAttributeNames={"#N": "name"}
    )
    if response['Count'] == 0:
        logger.info('Not found: %s', secret_name)
        return

    for secret in response["Items"]:
        logger.info("Deleting %s -- version %s",
                    secret["name"], secret["version"])
        secrets_table.delete_item(Key=secret)
    logger.info('Deleted %s', secret_name)
