from __future__ import absolute_import, division, print_function, unicode_literals

import botocore.exceptions


class KmsKeyService(object):
    def __init__(self, session, key_id, encryption_context=None):
        self.kms = session.client('kms')
        self.key_id = key_id
        if not encryption_context:
            encryption_context = {}
        self.encryption_context = encryption_context

    def generate_key_data(self, number_of_bytes, additional_authenticated_data=None):
        encryption_context = self._get_encryption_context(additional_authenticated_data)
        try:
            kms_response = self.kms.generate_data_key(
                KeyId=self.key_id, EncryptionContext=encryption_context, NumberOfBytes=int(number_of_bytes)
            )
        except:
            raise KmsError("Could not generate key using KMS key %s" % self.key_id)
        return kms_response['Plaintext'], kms_response['CiphertextBlob']

    def decrypt(self, encoded_key, additional_authenticated_data=None):
        encryption_context = self._get_encryption_context(additional_authenticated_data)
        try:
            kms_response = self.kms.decrypt(
                CiphertextBlob=encoded_key,
                EncryptionContext=encryption_context
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidCiphertextException":
                if self.encryption_context is None:
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
        return kms_response['Plaintext']

    def _get_encryption_context(self, additional_authenticated_data):
        encryption_context = {}
        if self.encryption_context:
            encryption_context.update(self.encryption_context)
        if additional_authenticated_data:
            encryption_context.update(additional_authenticated_data)
        return encryption_context

    def __repr__(self):
        return 'KmsKeyService(key_id={0},context={1})'.format(self.key_id, self.encryption_context)


class KmsError(Exception):

    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"

    def __str__(self):
        return self.value
