from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from boto3.dynamodb.conditions import Attr, Key as ConditionKey
from boto3.dynamodb.types import Binary

logger = logging.getLogger(__name__)


class ItemNotFound(Exception):
    pass


class DynamoDbStorageService(object):

    @property
    def binary_type(self):
        # DynamoDB wont put `str` => `Binary` in python2
        # So we need to advertise how we'd like the encryption
        #  service to wrap it's binary data.
        return Binary

    def __init__(self, session, table_name):
        self.dynamodb = session.resource('dynamodb')
        self.table_name = table_name
        self._secrets_table = None

    @property
    def secrets_table(self):
        if not self._secrets_table:
            self._secrets_table = self.dynamodb.Table(self.table_name)
        return self._secrets_table

    def list_one(self, name):
        response = self.secrets_table.scan(
            FilterExpression=Attr("name").eq(name),
            ProjectionExpression="#N, version",
            ExpressionAttributeNames={"#N": "name"}
        )
        return [
            self._unwrap_doc(item)
            for item in response['Items']
        ]

    def list_all(self):
        response = self.secrets_table.scan(
            ProjectionExpression="#N, version",
            ExpressionAttributeNames={"#N": "name"}
        )
        return [
            self._unwrap_doc(item)
            for item in response['Items']
        ]

    def delete_one(self, name, version):
        self.secrets_table.delete_item(Key={
            'name': name,
            'version': self._wrap_int(version)
        })

    def put_one(self, name, version, ciphertext):
        data = {
            'name': name,
            'version': self._wrap_int(version),
        }
        data.update(ciphertext)
        self.secrets_table.put_item(
            Item=data,
            ConditionExpression=Attr('name').not_exists()
        )

    def get_one(self, name, version=None):
        if not version:
            return self._get_latest_secret(name)
        else:
            return self._get_versioned_secret(name, version)

    def _get_latest_secret(self, secret_name):
        # do a consistent fetch of the credential with the highest version
        response = self.secrets_table.query(
            Limit=1,
            ScanIndexForward=False,
            ConsistentRead=True,
            KeyConditionExpression=ConditionKey("name").eq(secret_name)
        )
        if response["Count"] == 0:
            return
        return self._unwrap_doc(response["Items"][0])

    def _get_versioned_secret(self, secret_name, version):
        version = self._wrap_int(version)
        response = self.secrets_table.get_item(Key={"name": secret_name, "version": version})
        if "Item" not in response:
            return
        return self._unwrap_doc(response["Item"])

    @classmethod
    def _unwrap_doc(cls, obj):
        new_obj = {
            k: (v.value if isinstance(v, Binary) else v)
            for k, v in obj.items()
        }
        new_obj['version'] = cls._unwrap_int(new_obj['version'])
        return new_obj

    INT_FMT = '019d'

    @classmethod
    def _wrap_int(cls, i):
        if not isinstance(i, int):
            raise TypeError('Expected int, got %s instead' % type(i))
        return format(i, cls.INT_FMT)

    @classmethod
    def _unwrap_int(cls, txt):
        try:
            return int(txt, 10)
        except ValueError:
            raise RuntimeError('Could not unwrap as integer: %s' % txt)

    def setup(self, read_capacity=1, write_capacity=1):
        table_names = {t.name for t in self.dynamodb.tables.all()}
        if self.table_name in table_names:
            raise SetupError("Credential Store table already exists")

        logger.info('creating table "%s"...', self.table_name)
        self.dynamodb.create_table(
            TableName=self.table_name,
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
        self.dynamodb.get_waiter('table_exists').wait(TableName=self.table_name)

    def __repr__(self):
        return 'DynamoDbStorageService(table_name=%s)' % self.table_name


class SetupError(RuntimeError):
    pass
