# test credstash when imported as a library
# run using `pytest integration_tests/test_credstash_lib.py`
import credstash
import pytest

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


def test_deleteSecret(secret):
    secrets = credstash.listSecrets()
    del secret['value']
    assert secrets == [secret]

    credstash.deleteSecrets(secret['name'])
    secrets = credstash.listSecrets()
    assert secrets == []


def test_getSecret_nonexistent():
    try:
        credstash.getSecret("bad secret")
    except credstash.ItemNotFound:
        assert True
    else:
        assert False, "expected credstash.ItemNotFound error"