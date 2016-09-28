from __future__ import absolute_import, division, print_function, unicode_literals

from base64 import b64decode

import botocore.exceptions
from Crypto.Cipher import AES
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter
from boto3.dynamodb.conditions import Key as ConditionKey
from credsmash.util import ItemNotFound, KmsError, get_digest, IntegrityError, padded_int


def get_secret(secrets_table, kms, secret_name, version=None, encryption_context=None):
    if not encryption_context:
        encryption_context = {}

    if version is None:
        # do a consistent fetch of the credential with the highest version
        response = secrets_table.query(
            Limit=1,
            ScanIndexForward=False,
            ConsistentRead=True,
            KeyConditionExpression=ConditionKey("name").eq(secret_name)
        )
        if response["Count"] == 0:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found." % secret_name)
        material = response["Items"][0]
    else:
        version = padded_int(version)
        response = secrets_table.get_item(Key={"name": secret_name, "version": version})
        if "Item" not in response:
            raise ItemNotFound(
                "Item {'name': '%s', 'version': '%s'} couldn't be found." % (secret_name, version))
        material = response["Item"]

    # Check the HMAC before we decrypt to verify ciphertext integrity
    try:
        kms_response = kms.decrypt(
            CiphertextBlob=b64decode(material['key']),
            EncryptionContext=encryption_context
        )
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "InvalidCiphertextException":
            if encryption_context is None:
                msg = ("Could not decrypt hmac key with KMS. The credential may "
                       "require that an encryption context be provided to decrypt "
                       "it.")
            else:
                msg = ("Could not decrypt hmac key with KMS. The encryption "
                       "context provided may not match the one used when the "
                       "credential was stored.")
        else:
            msg = "Decryption error %s" % e
        raise KmsError(msg)
    except Exception as e:
        raise KmsError("Decryption error %s" % e)
    # Check for the existence of a digest value
    if 'digest' in material:
        digest = material['digest']
    else:
        digest = 'SHA256'

    key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    hmac = HMAC(hmac_key, msg=b64decode(material['contents']),
                digestmod=get_digest(digest))
    if hmac.hexdigest() != material['hmac']:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC"
                             % secret_name)
    dec_ctr = Counter.new(128)
    decryptor = AES.new(key, AES.MODE_CTR, counter=dec_ctr)
    plaintext = decryptor.decrypt(
        b64decode(material['contents'])).decode("utf-8")
    return plaintext
