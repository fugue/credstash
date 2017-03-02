#!/usr/bin/env python
# Copyright 2015 DevOpsyTurvy
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

from credstash import open_aes_ctr_legacy, seal_aes_ctr_legacy
from credstash import get_session, get_session_params
from credstash import get_assumerole_credentials
from credstash import KeyService, KmsError, IntegrityError, ItemNotFound
from credstash import KeyValueToDictionary, key_value_pair, expand_wildcard
from credstash import fatal, value_or_filename
from credstash import csv_dump, dotenv_dump
from credstash import clean_fail
from credstash import HASHING_ALGORITHMS, DEFAULT_DIGEST, DEFAULT_REGION
from credstash import WILDCARD_CHAR
import argparse
import json
import operator
import os
import os.path
import sys
import boto3
import botocore.exceptions

try:
    import yaml
    NO_YAML = False
except ImportError:
    NO_YAML = True

def getHighestVersion(name, region=None, location=None,
                      **kwargs):
    '''
    Return the highest version of `name` in the S3 location
    '''

    (bucket, prefix) = get_s3_bucket_prefix(location)
    secrets = listSecrets(region, bucket + "/" + prefix + name, **kwargs)

    if len(secrets) == 0:
        return 0
    return secrets[0]["version"]


def listSecrets(region=None, location=None, **kwargs):
    '''
    list all credentials stored in the S3 location,
    and return the names and latest versions of every credential
    '''
    session = get_session(**kwargs)
    client = session.client('s3', region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)
    response = client.list_objects_v2(Bucket=bucket,Prefix=prefix)
    if response.get("Contents"):
        # Get the list of all object in the S3 location
        # sorted by the modification date in reverse order
        secrets = sorted( [{ "name": item["Key"].split('/')[0], 
            "version": item["Key"].split('/')[1], 
            "datetime": item["LastModified"]} for item in response["Contents"] ],
            key=lambda s: s["datetime"],
            reverse=True)
        # Form an array with the latest versions of the objects only
        saved = set()
        saved_add = saved.add
        latest = [ item for item in secrets
                if not (item["name"] in saved or saved_add(item["name"])) ]
    else:
        latest = []

    return latest


def putSecret(name, secret, version="", kms_key="alias/creds3",
              region=None, location=None, context=None,
              digest=DEFAULT_DIGEST, **kwargs):
    '''
    put a secret called `name` into the secret-store,
    protected by the key kms_key
    '''
    if not context:
        context = {}
    session = get_session(**kwargs)
    kms = session.client('kms', region_name=region)
    key_service = KeyService(kms, kms_key, context)
    sealed = seal_aes_ctr_legacy(
        key_service,
        secret,
        digest_method=digest,
    )

    client = session.client('s3', region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)
    version_exists = True
    try:
        obj = client.get_object(Bucket = bucket,
            Key = prefix + name + "/" + version)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            client.put_object(Bucket = bucket,
                  Key = prefix + name + "/" + version,
                  Metadata = sealed[1],
                  Body = sealed[0]
                )
            version_exists = False
        else:
            fatal(e)

    if version_exists:
        latestVersion = getHighestVersion(name, region,
                                            location,
                                            **kwargs)
        fatal("%s version %s is already in the credential store. "
                "Use the -v flag to specify a new version" %
                (name, latestVersion))

    return True


def getAllSecrets(version="", region=None, location=None,
                  context=None, credential=None, session=None, **kwargs):
    '''
    fetch and decrypt all secrets
    '''
    output = {}
    if session is None:
        session = get_session(**kwargs)

    client = session.client('s3', region_name=region)
    kms = session.client('kms', region_name=region)
    secrets = listSecrets(region, location, **kwargs)
    print("DEBUG: secrets are '%s' " % secrets)

    for secret in secrets:
        credential = secret["name"]
        try:
            output[credential] = getSecret(credential,
                                           version,
                                           region,
                                           location,
                                           context,
                                           client,
                                           kms,
                                           **kwargs)
        except:
            pass
    return output


@clean_fail
def getAllAction(args, location, region, **session_params):
    secrets = getAllSecrets(args.version,
                            region=region,
                            location=location,
                            context=args.context,
                            **session_params)
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
    elif args.format == 'dotenv':
        output_func = dotenv_dump
        output_args = {}
    print(output_func(secrets, **output_args))


@clean_fail
def putSecretAction(args, location, region, **session_params):
    if args.autoversion:
        latestVersion = getHighestVersion(args.credential,
                                          region,
                                          location,
                                          **session_params)
        try:
            version = str(int(latestVersion) + 1)
        except ValueError:
            fatal("Can not autoincrement version. The current "
                  "version: %s is not an int" % latestVersion)
    else:
        version = args.version

    try:
        if putSecret(args.credential, args.value, version,
                     kms_key=args.key, region=region, location=location,
                     context=args.context, digest=args.digest,
                     **session_params):
            print("{0} has been stored".format(args.credential))
    except KmsError as e:
        fatal(e)
    except botocore.exceptions.ClientError as e:
        fatal(e)


@clean_fail
def getSecretAction(args, location, region, **session_params):
    try:
        if WILDCARD_CHAR in args.credential:
            names = expand_wildcard(args.credential,
                                    [x["name"]
                                     for x
                                     in listSecrets(region=region,
                                                    location=location,
                                                    **session_params)])
            print(json.dumps(dict((name,
                                   getSecret(name,
                                             args.version,
                                             region=region,
                                             location=location,
                                             context=args.context,
                                             **session_params))
                                  for name in names)))
        else:
            sys.stdout.write(getSecret(args.credential, args.version,
                                       region=region, location=location,
                                       context=args.context,
                                       **session_params))
            if not args.noline:
                sys.stdout.write("\n")
    except ItemNotFound as e:
        fatal(e)
    except KmsError as e:
        fatal(e)
    except IntegrityError as e:
        fatal(e)


def getSecret(name, version="", region=None,
              location=None, context=None,
              client=None, kms=None, **kwargs):
    '''
    fetch and decrypt the secret called `name`
    '''
    if not context:
        context = {}

    # Can we cache
    if client is None or kms is None:
        session = get_session(**kwargs)
        if client is None:
            client = session.client('s3', region_name=region)
        if kms is None:
            kms = session.client('kms', region_name=region)

    (bucket, prefix) = get_s3_bucket_prefix(location)

    if version == "":
        secrets = listSecrets(region, bucket + "/" + prefix + name, **kwargs)
        # do a consistent fetch of the credential with the highest version
        if secrets:
            obj = client.get_object(Bucket = bucket,
                    Key = prefix + name + "/" + secrets[0]["version"])
        else:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found in %s" %
                    name, location)
    else:
        obj = client.get_object(Bucket = bucket,
                    Key = prefix + name + "/" + version)
    material = { "contents": obj["Body"].read() }
    material.update(obj["Metadata"])

    key_service = KeyService(kms, None, context)

    return open_aes_ctr_legacy(key_service, material)


def get_s3_bucket_prefix(location):
    if location.find('/') > 0:
        bucket = location[:location.find('/')]
        prefix = location[location.find('/')+1:]
        if prefix[-1] != '/':
            prefix = prefix + '/'
    else:
        bucket = location
        prefix = ''
    return bucket, prefix

@clean_fail
def deleteSecrets(name, region=None, location=None, **kwargs):
    session = get_session(**kwargs)
    client = session.client('s3', region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)
    response = client.list_objects_v2(Bucket=bucket,Prefix=prefix + name)

    for secret in response["Contents"]:
        print("Deleting %s -- version %s" %
              (name, secret["Key"]))
        client.delete_object(Bucket=bucket,Key=secret["Key"])


@clean_fail
def createS3Bucket(region=None, location=None, **kwargs):
    '''
    create the secret store S3 bucket in the specified region
    '''
    session = get_session(**kwargs)
    client = session.client("s3", region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)

    try:
        response = client.create_bucket(ACL='private',
                Bucket=bucket,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                })
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "BucketAlreadyOwnedByYou":
            print("Credential Store bucket '%s' exists and owned by you" %
                    bucket)
        elif e.response["Error"]["Code"] == "BucketAlreadyExists":
            print("Bucket '%s' exists already - please use another name" %
                    bucket)
            return
        else:
            fatal(e)

    print("Checking the Credential Store bucket '%s' ..." % bucket)
    response = client.head_bucket(Bucket=bucket)
    customer_kms = response.get('ResponseMetadata').get('SSECustomerKeyMD5')
    if customer_kms:
        print("Looks like S3 bucket '%s' employs encryption with a "
                "customer  KMS key %s" % (bucket, customer_kms))
        print("This is not currently supported for Credential Store!")
        fatal(" ".join(["Disable encryption with customer KMS for %s",
                "or use different S3 bucket for Credential Store"]) % bucket)
    print("Credential Store is ok. "
          "Go read the README about how to create your KMS key")

@clean_fail
def list_credentials(region, location, **session_params):
    credential_list = listSecrets(region=region,
                                  location=location,
                                  **session_params)
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

def get_parser():
    """get the parsers dict"""
    parsers = {}
    parsers['super'] = argparse.ArgumentParser(
        description="A credential/secret storage system")

    parsers['super'].add_argument("-r", "--region",
                                  help="the AWS region in which to operate. "
                                  "If a region is not specified, creds3h "
                                  "will use the value of the "
                                  "AWS_DEFAULT_REGION env variable, "
                                  "or if that is not set, the value in "
                                  "`~/.aws/config`. As a last resort, "
                                  "it will use " + DEFAULT_REGION)
    parsers['super'].add_argument("-l", "--location",
                                  help="S3 location to use for "
                                  "credential storage")
    role_parse = parsers['super'].add_mutually_exclusive_group()
    role_parse.add_argument("-p", "--profile", default=None,
                            help="Boto config profile to use when "
                            "connecting to AWS")
    role_parse.add_argument("-n", "--arn", default=None,
                            help="AWS IAM ARN for AssumeRole")
    subparsers = parsers['super'].add_subparsers(help='Try commands like '
                                                 '"{name} get -h" or "{name} '
                                                 'put --help" to get each '
                                                 'sub command\'s options'
                                                 .format(name=sys.argv[0]))

    action = 'delete'
    parsers[action] = subparsers.add_parser(action,
                                 help='Delete a credential from the store')
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
                                 choices=["json", "csv", "dotenv"] +
                                 ([] if NO_YAML else ["yaml"]),
                                 help="Output format. json(default) " +
                                 ("" if NO_YAML else "yaml ") + " csv or dotenv.")
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
                                 "the value, or pass \"-\" to read the value "
                                 "from stdin", default="")
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-k", "--key", default="alias/creds3",
                                 help="the KMS key-id of the master key "
                                 "to use. See the README for more "
                                 "information. Defaults to alias/creds3")
    parsers[action].add_argument("-v", "--version", default="1",
                                 help="Put a specific version of the "
                                 "credential (update the credential; "
                                 "defaults to version `1`).")
    parsers[action].add_argument("-a", "--autoversion", action="store_true",
                                 help="Automatically increment the version of "
                                 "the credential to be stored. This option "
                                 "causes the `-v` flag to be ignored. "
                                 "(This option will fail if the currently stored "
                                 "version is not numeric.)")
    parsers[action].add_argument("-d", "--digest", default=DEFAULT_DIGEST,
                                 choices=HASHING_ALGORITHMS,
                                 help="the hashing algorithm used to "
                                 "to encrypt the data. Defaults to SHA256")
    parsers[action].set_defaults(action=action)

    action = 'setup'
    parsers[action] = subparsers.add_parser(action,
                                            help='setup the credential store')
    parsers[action].set_defaults(action=action)
    return parsers

def get_aws_account_id(session):
    sts = session.client("sts")
    user_arn = sts.get_caller_identity()["Arn"]
    return user_arn.split(":")[4]

def main():
    parsers = get_parser()
    args = parsers['super'].parse_args()

    # Check for assume role and set  session params
    session_params = get_session_params(args.profile, args.arn)

    try:
        region = args.region
        session = get_session(**session_params)
        session.client('s3', region_name=region)
        account_id = get_aws_account_id(session)
    except botocore.exceptions.NoRegionError:
        if 'AWS_DEFAULT_REGION' not in os.environ:
            region = DEFAULT_REGION

    location = args.location if args.location \
            else "credential-store-" + account_id

    if "action" in vars(args):
        if args.action == "delete":
            deleteSecrets(args.credential,
                          region=region,
                          location=location,
                          **session_params)
            return
        if args.action == "list":
            list_credentials(region, location, **session_params)
            return
        if args.action == "put":
            putSecretAction(args, location, region, **session_params)
            return
        if args.action == "get":
            getSecretAction(args, location, region, **session_params)
            return
        if args.action == "getall":
            getAllAction(args, location, region, **session_params)
            return
        if args.action == "setup":
            createS3Bucket(region=region, location=location,
                           **session_params)
            return
    else:
        parsers['super'].print_help()

if __name__ == '__main__':
    main()
