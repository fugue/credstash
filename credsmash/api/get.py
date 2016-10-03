from __future__ import absolute_import, division, print_function, unicode_literals

from boto3.dynamodb.types import Binary
from boto3.dynamodb.conditions import Key as ConditionKey
from credsmash.util import ItemNotFound, padded_int
from credsmash.crypto import open_secret


def get_secret(secrets_table, key_service, secret_name, version=None):
    if version is None:
        ciphertext = get_latest_secret(secrets_table, secret_name)
    else:
        ciphertext = get_versioned_secret(secrets_table, secret_name, version)

    return open_secret(key_service, ciphertext)


def _unwrap_dynamodb_types(obj):
    return {
        k: (v.value if isinstance(v, Binary) else v)
        for k, v in obj.items()
    }


def get_latest_secret(secrets_table, secret_name):
    # do a consistent fetch of the credential with the highest version
    response = secrets_table.query(
        Limit=1,
        ScanIndexForward=False,
        ConsistentRead=True,
        KeyConditionExpression=ConditionKey("name").eq(secret_name)
    )
    if response["Count"] == 0:
        raise ItemNotFound("Item {'name': '%s'} couldn't be found." % secret_name)
    return _unwrap_dynamodb_types(response["Items"][0])


def get_versioned_secret(secrets_table, secret_name, version):
    version = padded_int(version)
    response = secrets_table.get_item(Key={"name": secret_name, "version": version})
    if "Item" not in response:
        raise ItemNotFound(
            "Item {'name': '%s', 'version': '%s'} couldn't be found." % (secret_name, version))
    return _unwrap_dynamodb_types(response["Item"])
