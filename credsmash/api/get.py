from __future__ import absolute_import, division, print_function, unicode_literals

from credsmash.crypto import open_secret
from credsmash.util import ItemNotFound


def get_secret(storage_service, key_service, secret_name, version=None):
    ciphertext = storage_service.get_one(secret_name, version=version)
    if not ciphertext:
        raise ItemNotFound("Item {'name': '%s', 'version': %s} couldn't be found." % (secret_name, version))
    return open_secret(key_service, ciphertext)
