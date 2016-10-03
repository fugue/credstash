from __future__ import absolute_import, division, print_function, unicode_literals


def list_secrets(storage_service):
    return storage_service.list_all()
