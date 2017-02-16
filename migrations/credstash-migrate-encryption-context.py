#!/usr/bin/env python
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),"..")))

import credstash

def migrateSettingEncryptionContext(table="credential-store"):
    """ Re-encrypt all credentials which have no EncryptionContext.
    Sets a default EncryptionContext with the credential name and version number.

    No-op on credentials which have an EncryptionContext.
    """
    secrets = credstash.getAllSecrets(context={}, set_default_context=False)
    for name, secret in secrets.items():
        latestVersion = credstash.getHighestVersion(name, table=table)
        version = credstash.paddedInt(int(latestVersion) + 1)
        credstash.putSecret(name, secret, version, table=table)

if __name__ == "__main__":
    migrateSettingEncryptionContext()
