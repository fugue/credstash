from __future__ import absolute_import, division, print_function, unicode_literals

from boto3.dynamodb.conditions import Attr, Key as ConditionKey
from boto3.dynamodb.types import Binary
from credsmash.crypto import seal_secret, ALGO_AES_CTR
from credsmash.util import padded_int


def put_secret(
        secrets_table, key_service, secret_name,
        plaintext, version=None, algorithm=ALGO_AES_CTR, **seal_kwargs
):
    sealed = seal_secret(
        key_service,
        plaintext,
        algorithm=algorithm,
        binary_type=Binary,
        **seal_kwargs
    )

    if version is None:
        version = 1 + get_highest_version(
            secrets_table, secret_name
        )

    data = {
        'name': secret_name,
        'version': padded_int(version),
    }
    data.update(sealed)
    secrets_table.put_item(Item=data, ConditionExpression=Attr('name').not_exists())
    return version


def get_highest_version(secrets_table, secret_name):
    response = secrets_table.query(
        Limit=1,
        ScanIndexForward=False,
        ConsistentRead=True,
        KeyConditionExpression=ConditionKey("name").eq(secret_name),
        ProjectionExpression="version"
    )

    if response["Count"] == 0:
        return 0
    try:
        return int(response["Items"][0]["version"], 10)
    except ValueError:
        raise RuntimeError('Could not parse current version: %s' % response["Items"][0]["version"])
