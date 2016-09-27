from __future__ import absolute_import, division, print_function, unicode_literals

import logging

logger = logging.getLogger(__name__)


def create_secrets_table(dynamodb, table_name, read_capacity=1, write_capacity=1):
    table_names = {t.name for t in dynamodb.tables.all()}
    if table_name in table_names:
        raise SetupError("Credential Store table already exists")

    logger.info('creating table "%s"...', table_name)
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {
                "AttributeName": "name",
                "KeyType": "HASH",
            },
            {
                "AttributeName": "version",
                "KeyType": "RANGE",
            }
        ],
        AttributeDefinitions=[
            {
                "AttributeName": "name",
                "AttributeType": "S",
            },
            {
                "AttributeName": "version",
                "AttributeType": "S",
            },
        ],
        ProvisionedThroughput={
            "ReadCapacityUnits": read_capacity,
            "WriteCapacityUnits": write_capacity,
        }
    )
    logger.debug('Waiting for table to be created...')
    dynamodb.get_waiter('table_exists').wait(TableName=table_name)


class SetupError(RuntimeError):
    pass
