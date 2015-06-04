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
import operator
import os
import os.path
import sys
import time
import re
import json

from base64 import b64encode, b64decode
from boto.dynamodb2.exceptions import ConditionalCheckFailedException, ItemNotFound
from boto.dynamodb2.fields import HashKey, RangeKey
from boto.dynamodb2.table import Table
from boto.dynamodb2.types import STRING
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter

DEFAULT_REGION="us-east-1"
WILDCARD_CHAR="*"

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

class KeyValueToDictionary(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, 
                self.dest, 
                dict((x[0], x[1]) for (x[0], x[1]) in [x for x in values]))

    
def printStdErr(s):
    sys.stderr.write(str(s))
    sys.stderr.write("\n")

def key_value_pair(string):
    output = string.split('=')
    if len(output) != 2:
        msg = "%r is not the form of \"key=value\"" % string
        raise argparse.ArgumentTypeError(msg)
    return output

def expand_wildcard(string, secrets):
    prog = re.compile('^' + string.replace(WILDCARD_CHAR, '.*') + '$')
    output = []
    for secret in secrets:
        if prog.search(secret) is not None:
            output.append(secret)
    return output

def value_or_filename(string):
    if string[0] == "@":
        filename = string[1:]
        try:
            with open(os.path.expanduser(filename)) as f:
                output = f.read()
        except IOError as e:
            raise argparse.ArgumentTypeError("Unable to read file %s" % filename)
    else:
        output = string
    return output
    
def listSecrets(region="us-east-1", table="credential-store"):
    '''
    do a full-table scan of the credential-store and the names and versions of every credential
    '''
    secretStore = Table(table, connection=boto.dynamodb2.connect_to_region(region))
    rs = secretStore.scan(attributes=("name", "version"))
    return [secret for secret in rs]

def putSecret(name, secret, version, kms_key="alias/credstash", region="us-east-1", table="credential-store", context=None):
    '''
    put a secret called `name` into the secret-store, protected by the key kms_key
    '''
    kms = boto.kms.connect_to_region(region)
    # generate a a 64 byte key. Half will be for data encryption, the other half for HMAC
    try:
        kms_response = kms.generate_data_key(kms_key, context, 64)
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

    secretStore = Table(table, connection=boto.dynamodb2.connect_to_region(region))

    data = {}
    data['name'] = name
    data['version'] = version if version != "" else "1"
    data['key'] = b64encode(wrapped_key)
    data['contents'] = b64encode(c_text)
    data['hmac'] = b64hmac
    return secretStore.put_item(data=data)

def getSecret(name, version="", region="us-east-1", table="credential-store", context=None):
    '''
    fetch and decrypt the secret called `name`
    '''
    secretStore = Table(table, connection=boto.dynamodb2.connect_to_region(region))
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
        kms_response = kms.decrypt(b64decode(material['key']), context)
    except boto.kms.exceptions.InvalidCiphertextException:
        if context is None:
            msg = ("Could not decrypt hmac key with KMS. The credential may "
                   "require that an encryption context be provided to decrypt "
                   "it.")
        else:
            msg = ("Could not decrypt hmac key with KMS. The encryption "
                   "context provided may not match the one used when the "
                   "credential was stored.")
        raise KmsError(msg)
    except Exception as e:
        raise KmsError("Decryption error %s" % e)
    key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    hmac = HMAC(hmac_key, msg=b64decode(material['contents']), digestmod=SHA256)
    if hmac.hexdigest() != material['hmac']:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC" % name)
    dec_ctr = Counter.new(128)
    decryptor = AES.new(key, AES.MODE_CTR, counter=dec_ctr)
    plaintext = decryptor.decrypt(b64decode(material['contents']))
    return plaintext

def deleteSecrets(name, region="us-east-1", table="credential-store"):
    secretStore = Table(table, connection=boto.dynamodb2.connect_to_region(region))
    rs = secretStore.scan(name__eq = name)
    for i in rs:
        print("Deleting %s -- version %s" % (i["name"], i["version"]))
        i.delete()

def createDdbTable(region="us-east-1", table="credential-store"):
    '''
    create the secret store table in DDB in the specified region
    '''
    d_conn = boto.dynamodb2.connect_to_region(region)
    if table in d_conn.list_tables()['TableNames']:
        print("Credential Store table already exists")
        return
    print("Creating table...")
    secrets = Table.create(table, schema=[
        HashKey('name', data_type=STRING),
        RangeKey('version', data_type=STRING)
        ], throughput={
            'read':1,
            'write':1
        }, connection=d_conn)
    timeout = 1
    while secrets.describe()['Table']['TableStatus'] != "ACTIVE":
        print("Waiting for table to be created...")
        time.sleep(timeout)
        timeout = timeout * 2 if timeout < 8 else timeout
    print("Table has been created. Go read the README about how to create your KMS key")


def main():
    parsers = {}
    parsers['super'] = argparse.ArgumentParser(description="A credential/secret storage system")
    
    parsers['super'].add_argument("-r", "--region",  help="the AWS region in which to operate. If a region is not specified, credstash will use the value of the AWS_DEFAULT_REGION env variable, or if that is not set, us-east-1")
    parsers['super'].add_argument("-t", "--table", default="credential-store", help="DynamoDB table to use for credential storage")
    subparsers = parsers['super'].add_subparsers(help='Try commands like "{name} get -h" or "{name} put --help" to get each sub command\'s options'.format(name=os.path.basename(__file__)))

    action = 'delete'
    parsers[action] = subparsers.add_parser(action, help='Delete a credential from the store')
    parsers[action].add_argument("credential", type=str, help="the name of the credential to delete")
    parsers[action].set_defaults(action=action)

    action = 'get'
    parsers[action] = subparsers.add_parser(action, help='Get a credential from the store')
    parsers[action].add_argument("credential", type=str, help="the name of the credential to get. Using the wildcard character '%s' will search for credentials that match the pattern" % WILDCARD_CHAR)
    parsers[action].add_argument("context", type=key_value_pair, action=KeyValueToDictionary, nargs='*', help="encryption context key/value pairs associated with the credential in the form of \"key=value\"")
    parsers[action].add_argument("-k", "--key", default="alias/credstash", help="the KMS key-id of the master key to use. See the README for more information. Defaults to alias/credstash")
    parsers[action].add_argument("-n", "--noline", action="store_true", help="Don't append newline to returned value (useful in scripts or with binary files)")
    parsers[action].add_argument("-v", "--version", default="", help="Get a specific version of the credential (defaults to the latest version).")
    parsers[action].set_defaults(action=action)

    action = 'list'
    parsers[action] = subparsers.add_parser(action, help='list credentials and their versions')
    parsers[action].set_defaults(action=action)

    action = 'put'
    parsers[action] = subparsers.add_parser(action, help='Put a credential into the store')
    parsers[action].add_argument("credential", type=str, help="the name of the credential to store")
    parsers[action].add_argument("value", type=value_or_filename, help="the value of the credential to store or, if beginning with the \"@\" character, the filename of the file containing the value", default="")
    parsers[action].add_argument("context", type=key_value_pair, action=KeyValueToDictionary, nargs='*', help="encryption context key/value pairs associated with the credential in the form of \"key=value\"")
    parsers[action].add_argument("-k", "--key", default="alias/credstash", help="the KMS key-id of the master key to use. See the README for more information. Defaults to alias/credstash")
    parsers[action].add_argument("-v", "--version", default="", help="Put a specific version of the credential (update the credential; defaults to version `1`).")
    parsers[action].set_defaults(action=action)

    action = 'setup'
    parsers[action] = subparsers.add_parser(action, help='setup the credential store')
    parsers[action].set_defaults(action=action)
    
    args = parsers['super'].parse_args()
    region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION) if not args.region else args.region
    if args.action == "delete":
        deleteSecrets(args.credential, region=region, table=args.table)
        return
    if args.action == "list":
        credential_list = listSecrets(region=region, table=args.table)
        if credential_list:
            # print list of credential names and versions, sorted by name and then by version
            max_len = max([len(x["name"]) for x in credential_list])
            for cred in sorted(credential_list, key=operator.itemgetter("name", "version")):
                print("{0:{1}} -- version {2:>}".format(cred["name"], max_len, cred["version"])) 
        else:
            return 
    if args.action == "put":
        try:
            if putSecret(args.credential, args.value, args.version, kms_key=args.key, region=region, table=args.table, context=args.context):
                print("{0} has been stored".format(args.credential))
        except KmsError as e:
            printStdErr(e)
        except ConditionalCheckFailedException:
            printStdErr("%s version %s is already in the credential store. Use the -v flag to specify a new version" % (args.key, args.version if args.version != "" else "1"))
        return 
    if args.action == "get":
        try:
            if WILDCARD_CHAR in args.credential:
                names = expand_wildcard(args.credential, 
                                        [x["name"] 
                                         for x 
                                         in listSecrets(region=region, table=args.table)])
                print(json.dumps(dict((name,
                                      getSecret(name,
                                                args.version,
                                                region=region,
                                                table=args.table,
                                                context=args.context))
                                     for name in names)))
            else:
                sys.stdout.write(getSecret(args.credential, args.version, region=region, table=args.table, context=args.context))
                if not args.noline:
                    sys.stdout.write("\n")
        except ItemNotFound as e:
            printStdErr(e)
        except KmsError as e:
            printStdErr(e)
        except IntegrityError as e:
            printStdErr(e)        
        return
    if args.action == "setup":
        createDdbTable(region=region, table=args.table)
        return

if __name__ == '__main__':
    main()


