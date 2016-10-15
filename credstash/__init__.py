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
from __future__ import print_function

import argparse
import csv
import json
import os
import os.path
import re
import sys
from functools import partial

import credsmash

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

try:
    import yaml
    NO_YAML = False
except ImportError:
    NO_YAML = True

WILDCARD_CHAR = "*"


class KeyValueToDictionary(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace,
                self.dest,
                dict((x[0], x[1]) for x in values))


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

    if string == '-':
        try:
            return sys.stdin.read()
        except KeyboardInterrupt:
            raise argparse.ArgumentTypeError("Unable to read value from stdin")
    elif string[0] == "@":
        filename = string[1:]
        try:
            with open(os.path.expanduser(filename)) as f:
                output = f.read()
        except IOError:
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


def dotenv_dump(dictionary):
    dotenv_buffer = StringIO()
    for key in dictionary:
        dotenv_buffer.write("%s=%s\n" % (key.upper(), dictionary[key]))
    dotenv_buffer.seek(0)
    return dotenv_buffer.read()


def clean_fail(func):
    '''
    A decorator to cleanly exit on a failed call to AWS.
    catch a `botocore.exceptions.ClientError` raised from an action.
    This sort of error is raised if you are targeting a region that
    isn't set up (see, `credstash setup`.
    '''
    def func_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
    return func_wrapper


__output_formats = {
    'json': partial(json.dumps, sort_keys=True, indent=4, separators=(',', ': ')),
    'csv': csv_dump,
    'dotenv': dotenv_dump
}
if not NO_YAML:
    __output_formats['yaml'] = partial(yaml.dump, default_flow_style=False)


def get_parser():
    """get the parsers dict"""
    parsers = {}
    parsers['super'] = argparse.ArgumentParser(
        description="A credential/secret storage system")

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
    parsers[action].add_argument("-k", "--key", default="alias/credstash",
                                 help="the KMS key-id of the master key "
                                 "to use. See the README for more "
                                 "information. Defaults to alias/credstash")
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
    parsers[action].set_defaults(action=action)

    action = 'setup'
    parsers[action] = subparsers.add_parser(action,
                                            help='setup the credential store')
    parsers[action].set_defaults(action=action)
    return parsers


@clean_fail
def main():
    parsers = get_parser()
    args = parsers['super'].parse_args()
    session = credsmash.get_session(
        config='',  # disable loading from config file
        table_name=getattr(args, 'table', None),
        key_id=getattr(args, 'key', None),
        context=getattr(args, 'context', None)
    )
    if hasattr(args, 'action'):
        if args.action == "delete":
            session.delete_one(args.credential)
            return
        if args.action == "list":
            secrets = session.list_all()
            max_len = max([len(secret_name) for secret_name, _ in secrets])
            for secret_name, version in sorted(secrets):
                print("{0:{1}} -- version {2:>}".format(
                    secret_name, max_len, version))
            return
        if args.action == "put":
            if args.autoversion:
                version = None
            else:
                version = int(args.version)
            session.put_one(
                args.credential, args.value, version, compare=False
            )
            return
        if args.action == "get":
            if WILDCARD_CHAR in args.credential:
                secrets = session.find_many(args.credential)
                json.dump(sys.stdout, secrets)
            else:
                plaintext = session.get_one(args.credential, args.version or None)
                sys.stdout.write(plaintext)
                if not args.noline:
                    sys.stdout.write("\n")
            return
        if args.action == "getall":
            secrets = session.get_all()
            print(__output_formats[args.format](secrets))
            return
        if args.action == "setup":
            session.storage_service.setup()
            return
    else:
        parsers['super'].print_help()

if __name__ == '__main__':
    main()
