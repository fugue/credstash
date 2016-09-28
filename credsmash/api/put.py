from __future__ import absolute_import, division, print_function, unicode_literals

from boto3.dynamodb.conditions import Attr
from credsmash.aes_ctr import seal_aes_ctr_legacy
from credsmash.util import padded_int


def put_secret(
        secrets_table, key_service, secret_name,
        secret_value, secret_version, **seal_kwargs
):
    sealed = seal_aes_ctr_legacy(
        key_service,
        secret_value,
        **seal_kwargs
    )
    data = {
        'name': secret_name,
        'version': padded_int(secret_version),
    }
    data.update(sealed)
    return secrets_table.put_item(Item=data, ConditionExpression=Attr('name').not_exists())

