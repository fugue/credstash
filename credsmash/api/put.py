from __future__ import absolute_import, division, print_function, unicode_literals

from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Hash import *
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter
from boto3.dynamodb.conditions import Attr
from credsmash.util import padded_int, KmsError, get_digest, DEFAULT_DIGEST


def put_secret(
        secrets_table, kms, key_id, secret_name,
        secret_value, secret_version, context=None, digest=DEFAULT_DIGEST
):

    if not context:
        context = {}

    # generate a a 64 byte key.
    # Half will be for data encryption, the other half for HMAC
    try:
        kms_response = kms.generate_data_key(
            KeyId=key_id, EncryptionContext=context, NumberOfBytes=64
        )
    except:
        raise KmsError("Could not generate key using KMS key %s" % key_id)
    data_key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    wrapped_key = kms_response['CiphertextBlob']

    enc_ctr = Counter.new(128)
    encryptor = AES.new(data_key, AES.MODE_CTR, counter=enc_ctr)

    c_text = encryptor.encrypt(secret_value)
    # compute an HMAC using the hmac key and the ciphertext
    hmac = HMAC(hmac_key, msg=c_text, digestmod=get_digest(digest))

    b64hmac = hmac.hexdigest()

    data = {
        'name': secret_name,
        'version': padded_int(secret_version),
        'key': b64encode(wrapped_key).decode('utf-8'),
        'contents': b64encode(c_text).decode('utf-8'),
        'hmac': b64hmac,
        'digest': digest
    }

    return secrets_table.put_item(Item=data, ConditionExpression=Attr('name').not_exists())
