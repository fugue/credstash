from __future__ import absolute_import, division, print_function, unicode_literals

import csv
import importlib
import json
import logging

from six.moves import configparser

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


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


INT_FMT = '019d'

def padded_int(i):
    return format(i, INT_FMT)


DEFAULT_DIGEST = 'SHA256'
HASHING_ALGORITHMS = ['SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
                      'MD2', 'MD4', 'MD5', 'RIPEMD']

def get_digest(digest):
    try:
        return importlib.import_module('Crypto.Hash.{0}'.format(digest))
    except ImportError:
        raise ValueError("Could not find " + digest + " in Crypto.Hash")


def write_one(secret_name, secret_value, destination, format):
    if format == 'raw':
        destination.write(secret_value)
    else:
        write_many({secret_name: secret_value}, destination, format)


def write_many(secrets, destination, format):
    if format == 'csv':
        csvwriter = csv.writer(destination)
        for secret_name, secret_value in secrets.items():
            csvwriter.writerow([secret_name, secret_value])
        return

    if format == 'json':
        json.dump(secrets, destination, sort_keys=True, indent=4, separators=(',', ': '))
        return

    if format == 'yaml':
        if not HAS_YAML:
            raise RuntimeError('YAML Module not loaded. Please install with `pip install credsmash[yaml]`')
        yaml.dump(secrets, destination, default_flow_style=False)
        return

    raise RuntimeError('Unsupported format: %s' % format)


def read_one(secret_name, source, format):
    if format == 'raw':
        return source.read()

    secrets = read_many(source, format)
    return secrets[secret_name]


def read_many(source, format):
    if format == 'csv':
        csvreader = csv.DictReader(source, ['name', 'value'])
        return {
            entry['name']: entry['value']
            for entry in csvreader
        }

    if format == 'json':
        secrets = json.load(source)
    elif format == 'yaml':
        if not HAS_YAML:
            raise RuntimeError('YAML Module not loaded. Please install with `pip install credsmash[yaml]`')
        secrets = yaml.load(source)
    else:
        raise RuntimeError('Unsupported format: %s' % format)

    if not isinstance(secrets, dict):
        raise RuntimeError('Unsupported type: %s', type(secrets))
    for secret_name, secret_value in secrets.items():
        if not isinstance(secret_value, (str, unicode)):
            raise RuntimeError('Unsupported type: %s=%s', secret_name, type(secret_value))
    return secrets


def parse_config(fp):
    config = {}
    cp = configparser.RawConfigParser()
    cp.readfp(fp)
    for section in cp.sections():
        config[section] = {}
        for option in cp.options(section):
            config_value = cp.get(section, option)
            config[section][option] = config_value
    return config


def set_stream_logger(name='credsmash', level=logging.DEBUG, format_string=None):
    if format_string is None:
        format_string = "%(asctime)s %(name)s [%(levelname)s] %(message)s"

    logger = logging.getLogger(name)
    logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(format_string)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# Set up logging to ``/dev/null`` like a library is supposed to.
# http://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
class NullHandler(logging.Handler):
    def emit(self, record):
        pass


logging.getLogger('credsmash').addHandler(NullHandler())

