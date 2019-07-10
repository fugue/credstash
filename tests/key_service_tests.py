#!/usr/bin/env python
# Copyright 2015 Luminal, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import print_function

import unittest
import boto3 
from botocore.stub import Stubber

from credstash import KeyService, KmsError

class TestKeyService(unittest.TestCase):
    def test_generate_key_data_success(self):
        kms_client = boto3.client('kms')
        key_id = "test"
        encryption_context = {}
        with Stubber(kms_client) as stubber:
            stubber.add_response('generate_data_key', {
            'CiphertextBlob': b'ciphertext',
            'Plaintext': b'plaintext',
            'KeyId': 'string'
        }, expected_params = {
            'KeyId': key_id,
            'EncryptionContext': encryption_context,
            'NumberOfBytes': 1
        })
            key_service = KeyService(kms_client, key_id, encryption_context)
            response = key_service.generate_key_data(1)
        self.assertEqual(response[0], b'plaintext')
        self.assertEqual(response[1], b'ciphertext')

    def test_generate_key_data_error(self):
        kms_client = boto3.client('kms')
        key_id = "test"
        encryption_context = {}
        with Stubber(kms_client) as stubber:
            stubber.add_client_error(
                'generate_key_data', 
                'KeyUnavailableException',
                'The request was rejected because the specified CMK was not available. The request can be retried.',
                500,
                expected_params={
                    'KeyId': key_id,
                    'EncryptionContext': encryption_context,
                    'NumberOfBytes': 1
                })
            key_service = KeyService(kms_client, key_id, encryption_context)
            with self.assertRaises(KmsError) as e:
                key_service.generate_key_data(1)
                self.assertEqual(e, KmsError("Could not generate key using KMS key %s (Details: %s)" % (key_id, 'The request was rejected because the specified CMK was not available. The request can be retried.')))
    
    def test_decrypt_success(self):
        kms_client = boto3.client('kms')
        key_id = "test"
        encryption_context = {}
        with Stubber(kms_client) as stubber:
            stubber.add_response('decrypt', {
            'KeyId': 'key_id',
            'Plaintext': b'plaintext'
        }, expected_params = {
            'CiphertextBlob': 'encoded_key',
            'EncryptionContext': encryption_context
        })
            key_service = KeyService(kms_client, key_id, encryption_context)
            response = key_service.decrypt('encoded_key')
        self.assertEqual(response, b'plaintext')

    def test_decrypt_error(self):
        kms_client = boto3.client('kms')
        key_id = "test"
        encryption_context = {}
        with Stubber(kms_client) as stubber:
            stubber.add_client_error(
                'decrypt',
                'NotFoundException',
                'The request was rejected because the specified entity or resource could not be found.',
                400, 
                expected_params = {
                    'CiphertextBlob': 'encoded_key',
                    'EncryptionContext': encryption_context
            })
            key_service = KeyService(kms_client, key_id, encryption_context)
            with self.assertRaises(KmsError) as e:
                response = key_service.decrypt('encoded_key')
                self.assertEqual(e, KmsError("Decryption error The request was rejected because the specified entity or resource could not be found."))

    def test_decrypt_invalid_ciphertext_error_no_context(self):
        kms_client = boto3.client('kms')
        key_id = "test"
        encryption_context = {}
        with Stubber(kms_client) as stubber:
            stubber.add_client_error(
                'decrypt',
                'InvalidCiphertextException',
                'The request was rejected because the specified ciphertext, or additional authenticated data incorporated into the ciphertext, such as the encryption context, is corrupted, missing, or otherwise invalid.',
                400, 
                expected_params = {
                    'CiphertextBlob': 'encoded_key',
                    'EncryptionContext': encryption_context
            })
            key_service = KeyService(kms_client, key_id, encryption_context)
            with self.assertRaises(KmsError) as e:
                msg = ("Could not decrypt hmac key with KMS. The credential may "
                        "require that an encryption context be provided to decrypt "
                        "it.")
                response = key_service.decrypt('encoded_key')
                self.assertEqual(e, KmsError(msg))

    def test_decrypt_invalid_ciphertext_error_with_context(self):
        kms_client = boto3.client('kms')
        key_id = "test"
        encryption_context = {
            'key': 'value'
        }
        with Stubber(kms_client) as stubber:
            stubber.add_client_error(
                'decrypt',
                'InvalidCiphertextException',
                'The request was rejected because the specified ciphertext, or additional authenticated data incorporated into the ciphertext, such as the encryption context, is corrupted, missing, or otherwise invalid.',
                400, 
                expected_params = {
                    'CiphertextBlob': 'encoded_key',
                    'EncryptionContext': encryption_context
            })
            key_service = KeyService(kms_client, key_id, encryption_context)
            with self.assertRaises(KmsError) as e:
                msg = ("Could not decrypt hmac key with KMS. The encryption "
                        "context provided may not match the one used when the "
                        "credential was stored.")
                response = key_service.decrypt('encoded_key')
                self.assertEqual(e, KmsError(msg))                
        

