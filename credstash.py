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
import csv
import json
import operator
import os
import os.path
import sys
import time
import re
import boto3
import botocore.exceptions

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

try:
    import yaml
    NO_YAML = False
except ImportError:
    NO_YAML = True

from base64 import b64encode, b64decode
from boto3.dynamodb.conditions import Attr
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Util import Counter

DEFAULT_REGION = "us-east-1"
PAD_LEN = 19 # number of digits in sys.maxint
WILDCARD_CHAR = "*"


class KmsError(Exception):
    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"

    def __str__(self):
        return self.value


class IntegrityError(Exception):
    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else \
                     "INTEGRITY ERROR"

    def __str__(self):
        return self.value


class ItemNotFound(Exception):
    pass


class KeyValueToDictionary(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace,
                self.dest,
                dict((x[0], x[1]) for x in values))


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
    # argparse running on old version of python (<2.7) will pass an empty
    # string to this function before it passes the actual value.
    # If an empty string is passes in, just return an empty string
    if string == "":
        return ""
    if string[0] == "@":
        filename = string[1:]
        try:
            with open(os.path.expanduser(filename)) as f:
                output = f.read()
        except IOError as e:
            raise argparse.ArgumentTypeError("Unable to read file %s" %
                                             filename)
    else:
        output = string
    return output


def csv_dump(dictionary):
    csvfile = StringIO()
    csvwriter = csv.writer(csvfile)
    for key in dictionary:
        csvwriter.writerow([key, dictionary[key]])
    return csvfile.getvalue()


def paddedInt(i):
    '''
    return a string that contains `i`, left-padded with 0's up to PAD_LEN digits
    '''
    i_str = str(i)
    pad = PAD_LEN - len(i_str)
    return (pad * "0") + i_str

def getHighestVersion(name, region="us-east-1", table="credential-store"):
    '''
    Return the highest version of `name` in the table
    '''
    dynamodb = boto3.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.query(Limit=1,
                             ScanIndexForward=False,
                             ConsistentRead=True,
                             KeyConditionExpression=boto3.dynamodb.conditions.Key("name").eq(name),
                             ProjectionExpression="version")

    if response["Count"] == 0:
        return 0
    return response["Items"][0]["version"]


def listSecrets(region="us-east-1", table="credential-store"):
    '''
    do a full-table scan of the credential-store,
    and return the names and versions of every credential
    '''
    dynamodb = boto3.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.scan(ProjectionExpression="#N, version",
                            ExpressionAttributeNames={"#N": "name"})
    return response["Items"]


def putSecret(name, secret, version, kms_key="alias/credstash",
              region="us-east-1", table="credential-store", context=None):
    '''
    put a secret called `name` into the secret-store,
    protected by the key kms_key
    '''
    if not context:
        context = {}
    kms = boto3.client('kms', region_name=region)
    # generate a a 64 byte key.
    # Half will be for data encryption, the other half for HMAC
    try:
        kms_response = kms.generate_data_key(KeyId=kms_key, EncryptionContext=context, NumberOfBytes=64)
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

    dynamodb = boto3.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    data = {}
    data['name'] = name
    data['version'] = version if version != "" else paddedInt(1)
    data['key'] = b64encode(wrapped_key).decode('utf-8')
    data['contents'] = b64encode(c_text).decode('utf-8')
    data['hmac'] = b64hmac

    return secrets.put_item(Item=data, ConditionExpression=Attr('name').not_exists())


def getAllSecrets(version="", region="us-east-1",
                  table="credential-store", context=None):
    '''
    fetch and decrypt all secrets
    '''
    output = {}
    secrets = listSecrets(region, table)
    for credential in set([x["name"] for x in secrets]):
        try:
            output[credential] = getSecret(credential,
                                           version,
                                           region,
                                           table,
                                           context)
        except:
            pass
    return output


def getSecret(name, version="", region="us-east-1",
              table="credential-store", context=None):
    '''
    fetch and decrypt the secret called `name`
    '''
    if not context:
        context = {}

    dynamodb = boto3.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    if version == "":
        # do a consistent fetch of the credential with the highest version
        response = secrets.query(Limit=1,
                                 ScanIndexForward=False,
                                 ConsistentRead=True,
                                 KeyConditionExpression=boto3.dynamodb.conditions.Key("name").eq(name))
        if response["Count"] == 0:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found." % name)
        material = response["Items"][0]
    else:
        response = secrets.get_item(Key={"name": name, "version": version})
        if "Item" not in response:
            raise ItemNotFound("Item {'name': '%s', 'version': '%s'} couldn't be found." % (name, version))
        material = response["Item"]

    kms = boto3.client('kms', region_name=region)
    # Check the HMAC before we decrypt to verify ciphertext integrity
    try:
        kms_response = kms.decrypt(CiphertextBlob=b64decode(material['key']), EncryptionContext=context)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "InvalidCiphertextException":
            if context is None:
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
    except Exception as e:
        raise KmsError("Decryption error %s" % e)
    key = kms_response['Plaintext'][:32]
    hmac_key = kms_response['Plaintext'][32:]
    hmac = HMAC(hmac_key, msg=b64decode(material['contents']),
                digestmod=SHA256)
    if hmac.hexdigest() != material['hmac']:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC"
                             % name)
    dec_ctr = Counter.new(128)
    decryptor = AES.new(key, AES.MODE_CTR, counter=dec_ctr)
    plaintext = decryptor.decrypt(b64decode(material['contents'])).decode("utf-8")
    return plaintext


def deleteSecrets(name, region="us-east-1", table="credential-store"):
    dynamodb = boto3.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.scan(FilterExpression=boto3.dynamodb.conditions.Attr("name").eq(name),
                            ProjectionExpression="#N, version",
                            ExpressionAttributeNames={"#N": "name"})

    for secret in response["Items"]:
        print("Deleting %s -- version %s" % (secret["name"], secret["version"]))
        secrets.delete_item(Key=secret)


def createDdbTable(region="us-east-1", table="credential-store"):
    '''
    create the secret store table in DDB in the specified region
    '''
    dynamodb = boto3.resource("dynamodb", region_name=region)
    if table in (t.name for t in dynamodb.tables.all()):
        print("Credential Store table already exists")
        return

    print("Creating table...")
    response = dynamodb.create_table(
        TableName=table,
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
            "ReadCapacityUnits": 1,
            "WriteCapacityUnits": 1,
        }
    )

    print("Waiting for table to be created...")
    client = boto3.client("dynamodb", region_name=region)
    client.get_waiter("table_exists").wait(TableName=table)

    print("Table has been created. "
          "Go read the README about how to create your KMS key")


def main():
    parsers = {}
    parsers['super'] = argparse.ArgumentParser(
        description="A credential/secret storage system")

    parsers['super'].add_argument("-r", "--region",
                                  help="the AWS region in which to operate."
                                  "If a region is not specified, credstash "
                                  "will use the value of the "
                                  "AWS_DEFAULT_REGION env variable, "
                                  "or if that is not set, us-east-1")
    parsers['super'].add_argument("-t", "--table", default="credential-store",
                                  help="DynamoDB table to use for "
                                  "credential storage")
    subparsers = parsers['super'].add_subparsers(help='Try commands like '
                                                 '"{name} get -h" or "{name}'
                                                 'put --help" to get each'
                                                 'sub command\'s options'
                                                 .format(name=os.path.basename(
                                                         __file__)))

    action = 'delete'
    parsers[action] = subparsers.add_parser(action,
                                            help='Delete a credential " \
                                            "from the store')
    parsers[action].add_argument("credential", type=str,
                                 help="the name of the credential to delete")
    parsers[action].set_defaults(action=action)

    action = 'get'
    parsers[action] = subparsers.add_parser(action, help="Get a credential "
                                            "from the store")
    parsers[action].add_argument("credential", type=str,
                                 help="the name of the credential to get."
                                 "Using the wildcard character '%s' will "
                                 "search for credentials that match the "
                                 "pattern" % WILDCARD_CHAR)
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-n", "--noline", action="store_true",
                                 help="Don't append newline to returned "
                                 "value (useful in scripts or with "
                                 "binary files)")
    parsers[action].add_argument("-v", "--version", default="",
                                 help="Get a specific version of the "
                                 "credential (defaults to the latest version)")
    parsers[action].set_defaults(action=action)

    action = 'getall'
    parsers[action] = subparsers.add_parser(action,
                                            help="Get all credentials from "
                                            "the store")
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-v", "--version", default="",
                                 help="Get a specific version of the "
                                 "credential (defaults to the latest version)")
    parsers[action].add_argument("-f", "--format", default="json",
                                 choices=["json", "csv"] +
                                 ([] if NO_YAML else ["yaml"]),
                                 help="Output format. json(default) " +
                                 ("" if NO_YAML else "yaml ") + "or csv.")
    parsers[action].set_defaults(action=action)

    action = 'list'
    parsers[action] = subparsers.add_parser(action,
                                            help="list credentials and "
                                            "their versions")
    parsers[action].set_defaults(action=action)

    action = 'put'
    parsers[action] = subparsers.add_parser(action,
                                            help="Put a credential into "
                                            "the store")
    parsers[action].add_argument("credential", type=str,
                                 help="the name of the credential to store")
    parsers[action].add_argument("value", type=value_or_filename,
                                 help="the value of the credential to store "
                                 "or, if beginning with the \"@\" character, "
                                 "the filename of the file containing "
                                 "the value", default="")
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-k", "--key", default="alias/credstash",
                                 help="the KMS key-id of the master key "
                                 "to use. See the README for more "
                                 "information. Defaults to alias/credstash")
    parsers[action].add_argument("-v", "--version", default="",
                                 help="Put a specific version of the "
                                 "credential (update the credential; "
                                 "defaults to version `1`).")
    parsers[action].add_argument("-a", "--autoversion", action="store_true",
                                help="Automatically increment the version of "
                                "the credential to be stored. This option "
                                "causes the `-v` flag to be ignored. "
                                "(This option will fail if the currently stored "
                                "version is not numeric.)")
    parsers[action].set_defaults(action=action)

    action = 'setup'
    parsers[action] = subparsers.add_parser(action,
                                            help='setup the credential store')
    parsers[action].set_defaults(action=action)

    args = parsers['super'].parse_args()

    region = os.getenv(
        "AWS_DEFAULT_REGION", DEFAULT_REGION) if not args.region \
        else args.region
    if "action" in vars(args):
        if args.action == "delete":
            deleteSecrets(args.credential, region=region, table=args.table)
            return
        if args.action == "list":
            credential_list = listSecrets(region=region, table=args.table)
            if credential_list:
                # print list of credential names and versions,
                # sorted by name and then by version
                max_len = max([len(x["name"]) for x in credential_list])
                for cred in sorted(credential_list,
                                   key=operator.itemgetter("name", "version")):
                    print("{0:{1}} -- version {2:>}".format(
                        cred["name"], max_len, cred["version"]))
            else:
                return
        if args.action == "put":
            if args.autoversion:
                latestVersion = getHighestVersion(args.credential, region,
                                                  args.table)
                try:
                    version = paddedInt(int(latestVersion) + 1)
                except ValueError:
                    printStdErr("Can not autoincrement version. The current "
                                "version: %s is not an int" % latestVersion)
                    return
            else:
                version = args.version
            try:
                if putSecret(args.credential, args.value, version,
                             kms_key=args.key, region=region, table=args.table,
                             context=args.context):
                    print("{0} has been stored".format(args.credential))
            except KmsError as e:
                printStdErr(e)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    latestVersion = getHighestVersion(args.credential, region,
                                                      args.table)
                    printStdErr("%s version %s is already in the credential store. "
                                "Use the -v flag to specify a new version" %
                                (args.credential, latestVersion))
                return
        if args.action == "get":
            try:
                if WILDCARD_CHAR in args.credential:
                    names = expand_wildcard(args.credential,
                                            [x["name"]
                                             for x
                                             in listSecrets(region=region,
                                                            table=args.table)])
                    print(json.dumps(dict((name,
                                          getSecret(name,
                                                    args.version,
                                                    region=region,
                                                    table=args.table,
                                                    context=args.context))
                                          for name in names)))
                else:
                    sys.stdout.write(getSecret(args.credential, args.version,
                                               region=region, table=args.table,
                                               context=args.context))
                    if not args.noline:
                        sys.stdout.write("\n")
            except ItemNotFound as e:
                printStdErr(e)
            except KmsError as e:
                printStdErr(e)
            except IntegrityError as e:
                printStdErr(e)
            return
        if args.action == "getall":
            secrets = getAllSecrets(args.version,
                                    region=region,
                                    table=args.table,
                                    context=args.context)
            if args.format == "json":
                output_func = json.dumps
                output_args = {"sort_keys": True,
                               "indent": 4,
                               "separators": (',', ': ')}
            elif not NO_YAML and args.format == "yaml":
                output_func = yaml.dump
                output_args = {"default_flow_style": False}
            elif args.format == 'csv':
                output_func = csv_dump
                output_args = {}
            print(output_func(secrets, **output_args))
            return
        if args.action == "setup":
            createDdbTable(region=region, table=args.table)
            return
    else:
        parsers['super'].print_help()

if __name__ == '__main__':
    main()
