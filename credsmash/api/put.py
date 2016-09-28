from __future__ import absolute_import, division, print_function, unicode_literals

import six
from boto3.dynamodb.types import Binary
from boto3.dynamodb.conditions import Attr
from credsmash.aes_ctr import seal_aes_ctr_legacy, seal_aes_ctr, ALGO_AES_CTR, ALGO_AES_CTR_LEGACY
from credsmash.aes_gcm import seal_aes_gcm, ALGO_AES_GCM
from credsmash.util import padded_int


def put_secret(
        secrets_table, key_service, secret_name,
        secret_value, secret_version, algorithm=ALGO_AES_CTR, **seal_kwargs
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
    data = {
        'name': secret_name,
        'version': padded_int(secret_version),
    }
    data.update(sealed)
    return secrets_table.put_item(Item=data, ConditionExpression=Attr('name').not_exists())

