from __future__ import absolute_import, division, print_function, unicode_literals

import six
from boto3.dynamodb.types import Binary
from boto3.dynamodb.conditions import Attr, Key as ConditionKey
from credsmash.aes_ctr import seal_aes_ctr_legacy, seal_aes_ctr, ALGO_AES_CTR, ALGO_AES_CTR_LEGACY
from credsmash.aes_gcm import seal_aes_gcm, ALGO_AES_GCM
from credsmash.util import padded_int


def put_secret(
        secrets_table, key_service, secret_name,
        secret_value, version=None, algorithm=ALGO_AES_CTR, **seal_kwargs
):
    if isinstance(secret_value, six.text_type):
        secret_value = secret_value.encode('utf-8')
    if algorithm == ALGO_AES_GCM:
        sealed = seal_aes_gcm(
            key_service,
            secret_value,
            binary_type=Binary,
            **seal_kwargs
        )
    elif algorithm == ALGO_AES_CTR:
        sealed = seal_aes_ctr(
            key_service,
            secret_value,
            binary_type=Binary,
            **seal_kwargs
        )
    elif algorithm == ALGO_AES_CTR_LEGACY:
        sealed = seal_aes_ctr_legacy(
            key_service,
            secret_value,
            **seal_kwargs
        )
    else:
        raise RuntimeError('Unsupported algo: %s' % algorithm)

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
