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

import argparse
import boto.dynamodb2
import boto.kms
import sys
import time

from base64 import b64encode, b64decode
from boto.dynamodb2.exceptions import ConditionalCheckFailedException, ItemNotFound
from boto.dynamodb2.fields import HashKey, RangeKey
from boto.dynamodb2.table import Table
from boto.dynamodb2.types import STRING
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter


class KmsError(Exception):
    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"
    def __str__(self):
        return self.value

class IntegrityError(Exception):
    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else "INTEGRITY ERROR"
    def __str__(self):
        return self.value

    
def printStdErr(s):
    sys.stderr.write(str(s))
    sys.stderr.write("\n")

    
def listSecrets(region="us-east-1"):
    '''
    do a full-table scan of the credential-store and the names and versions of every credential
    '''
    secretStore = Table('credential-store', connection=boto.dynamodb2.connect_to_region(region))
    rs = secretStore.scan(attributes=("name", "version"))
    return [secret for secret in rs]

def putSecret(name, secret, version, kms_key="alias/credstash", region="us-east-1"):
    '''
    put a secret called `name` into the secret-store, protected by the key kms_key
    '''
    kms = boto.kms.connect_to_region(region)
    # generate a a 64 byte key. Half will be for data encryption, the other half for HMAC
    try:
        kms_response = kms.generate_data_key(kms_key, number_of_bytes=64)
    except:
        raise KmsError("Could not generate key using KMS key %s" % kms_key)
    data_key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    wrapped_key = kms_response['CiphertextBlob']
    
    enc_ctr = Counter.new(128)
    encryptor = AES.new(data_key, AES.MODE_CTR, counter=enc_ctr)

    c_text = encryptor.encrypt(secret)
    # compute an HMAC using the hmac key and the ciphertext
    hmac = HMAC(hmac_key, msg=c_text, digestmod=SHA256)
    b64hmac = hmac.hexdigest()

    secretStore = Table('credential-store', connection=boto.dynamodb2.connect_to_region(region))

    data = {}
    data['name'] = name
    data['version'] = version if version != "" else "1"
    data['key'] = b64encode(wrapped_key)
    data['contents'] = b64encode(c_text)
    data['hmac'] = b64hmac
    return secretStore.put_item(data=data)

def getSecret(name, version="", region="us-east-1"):
    '''
    fetch and decrypt the secret called `name`
    '''
    secretStore = Table('credential-store', connection=boto.dynamodb2.connect_to_region(region))
    if version == "":
        # do a consistent fetch of the credential with the highest version
        result_set = [x for x in secretStore.query_2(limit=1, reverse=True, consistent=True, name__eq=name)]
        if not result_set:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found." % name)
        material = result_set[0]
    else:
        material = secretStore.get_item(name=name, version=version)

    kms = boto.kms.connect_to_region(region)
    # Check the HMAC before we decrypt to verify ciphertext integrity
    try:
        kms_response = kms.decrypt(b64decode(material['key']))
    except:
        raise KmsError("Could not decrypt hmac key with KMS")
    key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    hmac = HMAC(hmac_key, msg=b64decode(material['contents']), digestmod=SHA256)
    if hmac.hexdigest() != material['hmac']:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC" % name)
    dec_ctr = Counter.new(128)
    decryptor = AES.new(key, AES.MODE_CTR, counter=dec_ctr)
    plaintext = decryptor.decrypt(b64decode(material['contents']))
    return plaintext

def deleteSecrets(name, region="us-east-1"):
    secretStore = Table('credential-store', connection=boto.dynamodb2.connect_to_region(region))
    rs = secretStore.scan(name__eq = name)
    for i in rs:
        print("Deleting %s -- version %s" % (i["name"], i["version"]))
        i.delete()

def createDdbTable(region="us-east-1"):
    '''
    create the secret store table in DDB in the specified region
    '''
    d_conn = boto.dynamodb2.connect_to_region(region)
    if 'credential-store' in d_conn.list_tables()['TableNames']:
        print("Credential Store table already exists")
        return
    print("Creating table...")
    secrets = Table.create('credential-store', schema=[
        HashKey('name', data_type=STRING),
        RangeKey('version', data_type=STRING)
        ], throughput={
            'read':1,
            'write':1
        }
        )
    timeout = 1
    while secrets.describe()['Table']['TableStatus'] != "ACTIVE":
        print("Waiting for table to be created...")
        time.sleep(timeout)
        timeout = timeout * 2 if timeout < 8 else timeout
    print("Table has been created. Go read the README about how to create your KMS key")


def main():
    parser = argparse.ArgumentParser(description="A credential/secret storage system")
    
    parser.add_argument("action", type=str, choices=["delete", "get", "list", "put", "setup"], help="Put, Get, or Delete a credential from the store, list credentials and their versions, or setup the credential store")
    parser.add_argument("credential", type=str, help="the name of the credential to store/get", nargs='?')
    parser.add_argument("value", type=str, help="the value of the credential to put (ignored if action is 'get')", nargs='?', default="")

    parser.add_argument("-i", "--infile", default="", help="store the contents of `infile` rather than provide a value on the command line")
    parser.add_argument("-k", "--key", default="alias/credstash", help="the KMS key-id of the master key to use. See the README for more information. Defaults to alias/credstash")
    parser.add_argument("-r", "--region", default="us-east-1", help="the AWS region in which to operate")
    parser.add_argument("-v", "--version", default="", help="If doing a `put`, put a specific version of the credential (update the credential; defaults to version `1`). If doing a `get`, get a specific version of the credential (defaults to the latest version).")
    
    args = parser.parse_args()
    if args.action == "delete":
        deleteSecrets(args.credential, region=args.region)
        return
    if args.action == "list":
        credential_list = listSecrets(region=args.region)
        if credential_list:
            # print list
            max_len = max([len(x["name"]) for x in credential_list])
            for cred in credential_list:
                print("{0:{1}} -- version {2:>}".format(cred["name"], max_len, cred["version"])) 
        else:
            return 
    if args.action == "put":
        if args.infile != "":
            f = open(args.infile)
            value_to_put = f.read()
            f.close()
        else:
            value_to_put = args.value
        try:
            if putSecret(args.credential, value_to_put, args.version, kms_key=args.key, region=args.region):
                print("{0} has been stored".format(args.credential))
        except KmsError as e:
            printStdErr(e)
        except ConditionalCheckFailedException:
            printStdErr("%s version %s is already in the credential store. Use the -v flag to specify a new version" % (args.key, args.version if args.version != "" else "1"))
        return 
    if args.action == "get":
        try:
            print(getSecret(args.credential, args.version, region=args.region))
        except ItemNotFound as e:
            printStdErr(e)
        except KmsError as e:
            printStdErr(e)
        except IntegrityError as e:
            printStdErr(e)        
        return
    if args.action == "setup":
        createDdbTable(args.region)
        return

if __name__ == '__main__':
    main()


