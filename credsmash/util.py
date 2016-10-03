from __future__ import absolute_import, division, print_function, unicode_literals

import csv
import json
import logging
import re
import os

import six
from six.moves import configparser

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)


class ItemNotFound(Exception):
    pass


def detect_format(fo, default_format):
    fname = getattr(fo, 'name', None)
    if fname:
        ext = os.path.splitext(fname)[-1].lower()
        if ext == '.json':
            return 'json'
        if ext == '.yml' or ext == '.yaml':
            return 'yaml'
        if ext == '.csv':
            return 'csv'
    return default_format


def write_one(secret_name, secret_value, destination, format):
    if format == 'raw':
        destination.write(secret_value)
    else:
        write_many({secret_name: secret_value}, destination, format)


def write_many(secrets, destination, format):
    if format == 'csv':
        # XX - current csv writer doesn't support unicode, so force to ascii
        secrets = dict(encode_strings(secrets, encoding='ascii'))
        csvwriter = csv.writer(destination)
        for secret_name, secret_value in secrets.items():
            csvwriter.writerow([secret_name, secret_value])
        return

    # Both JSON/YAML support unicode, so this should be fine
    secrets = dict(encode_strings(secrets, encoding='utf-8'))
    if format == 'json':
        json.dump(secrets, destination, sort_keys=True, indent=4, separators=(',', ': '))
        return

    if format == 'yaml':
        if not HAS_YAML:
            raise RuntimeError('YAML Module not loaded. Please install with `pip install credsmash[yaml]`')
        # Using safe_dump prevents it adding all the "!!python/unicode" annotations
        yaml.safe_dump(
            secrets, destination, default_flow_style=False,
            encoding='utf-8', allow_unicode=True
        )
        return

    raise RuntimeError('Unsupported format: %s' % format)


def encode_strings(secrets, encoding):
    for secret_name, secret_value in secrets.items():
        if isinstance(secret_value, six.binary_type):
            try:
                secret_value = secret_value.decode(encoding)
            except UnicodeDecodeError:
                logger.warning('Could not decode %s as utf-8.', secret_name)
                # Skip this secret
                continue
        yield secret_name, secret_value


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


def parse_manifest(source, format):
    if format == 'json':
        return json.load(source)
    if format == 'yaml':
        if not HAS_YAML:
            raise RuntimeError('YAML Module not loaded. Please install with `pip install credsmash[yaml]`')
        return yaml.load(source)
    raise RuntimeError('Unsupported format: %s' % format)


def parse_config(fp):
    config = {}
    cp = configparser.RawConfigParser()
    cp.readfp(fp)
    for section in cp.sections():
        config[section] = {}
        for option in cp.options(section):
            config_value = cp.get(section, option)
            if config_value.startswith("\n"):
                config_value = _parse_nested(config_value)
            config[section][option] = config_value
    return config


def _parse_nested(config_value):
    # Given a value like this:
    # \n
    # foo = bar
    # bar = baz
    # We need to parse this into
    # {'foo': 'bar', 'bar': 'baz}
    parsed = {}
    for line in config_value.splitlines():
        line = line.strip()
        if not line:
            continue
        # The caller will catch ValueError
        # and raise an appropriate error
        # if this fails.
        key, value = line.split('=', 1)
        parsed[key.strip()] = value.strip()
    return parsed


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


_find_unsafe = re.compile(r'[a-zA-Z0-9_^@%+=:,./-]').search


def shell_quote(s):
    """Return a shell-escaped version of the string *s*."""
    if not s:
        return "''"

    if _find_unsafe(s) is None:
        return s

    # use single quotes, and put single quotes into double quotes
    # the string $'b is then quoted as '$'"'"'b'

    return "'" + s.replace("'", "'\"'\"'") + "'"

