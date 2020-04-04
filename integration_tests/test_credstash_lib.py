# test credstash when imported as a library
# run using `pytest integration_tests/test_credstash_lib.py`
import credstash
import pytest
import botocore.exceptions

@pytest.yield_fixture
def secret():
    secret = {
        'name': 'test',
        'version': '0000000000000000000',
        'value': 'secret'
    }
    credstash.putSecret(secret['name'], secret['value'])
    try:
        yield secret
    finally:
        credstash.deleteSecrets("test")

def test_listSecrets(secret):
    secrets = credstash.listSecrets()
    del secret['value']
    assert secrets == [secret]


def test_getSecret(secret):
    s = credstash.getSecret(secret['name'])
    assert s == secret['value']


def test_getSecret_wrong_region(secret):
    try:
        credstash.getSecret(secret['name'], region='us-west-2')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            assert True
    else:
        assert False, "expected botocore ResourceNotFoundException"

def test_getSecret_nonexistent():
    try:
        credstash.getSecret("bad secret")
    except credstash.ItemNotFound:
        assert True
    else:
        assert False, "expected credstash.ItemNotFound error"


def test_getAllSecrets(secret):
    s = credstash.getAllSecrets()
    assert s == {secret['name']:secret['value']}


def test_getAllSecrets_no_secrets():
    s = credstash.getAllSecrets()
    assert s == dict()


def test_deleteSecret(secret):
    secrets = credstash.listSecrets()
    del secret['value']
    assert secrets == [secret]

    credstash.deleteSecrets(secret['name'])
    secrets = credstash.listSecrets()
    assert secrets == []        