from __future__ import absolute_import, division, print_function

import codecs
import fnmatch
import logging
import operator
import os
import sys

import boto3
import click
import pkg_resources

import credsmash.api
from credsmash.crypto import ALGO_AES_CTR
from credsmash.util import set_stream_logger, detect_format, \
    parse_config, read_one, read_many, write_one, write_many

logger = logging.getLogger(__name__)


class Environment(object):
    def __init__(self, storage_service_name, storage_service_config,
                 key_service_name, key_service_config,
                 algorithm, algorithm_options):
        self._storage_service = None
        self.storage_service_name = storage_service_name
        self.storage_service_config = storage_service_config
        self._key_service = None
        self.key_service_name = key_service_name
        self.key_service_config = key_service_config
        self.algorithm = algorithm
        self.algorithm_options = algorithm_options
        self._session = None

    @property
    def session(self):
        if self._session is None:
           self._session = boto3.Session()
        return self._session

    @staticmethod
    def load_entry_point(group, name):
        entry_points = pkg_resources.iter_entry_points(
            group, name
        )
        for entry_point in entry_points:
            return entry_point.load()
        raise RuntimeError('Not found EntryPoint(group={0},name={1})'.format(group, name))

    @property
    def key_service(self):
        if not self._key_service:
            cls = self.load_entry_point('credsmash.key_service', self.key_service_name)
            self._key_service = cls(
                session=self.session,
                **self.key_service_config
            )
            logger.debug('key_service=%r', self._key_service)
        return self._key_service

    @property
    def storage_service(self):
        if not self._storage_service:
            cls = self.load_entry_point('credsmash.storage_service', self.storage_service_name)
            self._storage_service = cls(
                session=self.session,
                **self.storage_service_config
            )
            logger.debug('storage_service=%r', self._storage_service)
        return self._storage_service

    def __repr__(self):
        return 'Environment(storage_service=%r,key_service=%r)' % (self._storage_service, self._key_service)


@click.group()
@click.option('--config', '-c',
              envvar='CREDSMASH_CONFIG',
              type=click.Path(resolve_path=True),
              default='/etc/credsmash.cfg')
@click.option('--table-name', '-t', default=None,
              help="DynamoDB table to use for "
                   "credential storage")
@click.option('--key-id', '-k', default=None,
              help="the KMS key-id of the master key "
                   "to use. See the README for more "
                   "information. Defaults to alias/credsmash")
@click.option('--context', type=(unicode, unicode), multiple=True,
              help="the KMS encryption context to use."
                   "Only works if --key-id is passed.")
@click.pass_context
def main(ctx, config, table_name, key_id, context=None):
    config_data = {}
    sections = {}
    if os.path.exists(config):
        with codecs.open(config, 'r') as config_fp:
            sections = parse_config(config_fp)
            config_data = sections.get('credsmash', {})

    if key_id:
        # Using --key-id/-k will ignore the configuration file.
        key_service_name = 'kms'
        key_service_config = {
            'key_id': key_id
        }
        if context:
            key_service_config['encryption_context'] = dict(context)
    else:
        if context:
            logger.warning('--context can only be used in conjunction with --key-id')
        key_service_name = config_data.get('key_service', 'kms')
        key_service_config = sections.get('credsmash:key_service:%s' % key_service_name, {})
        if key_service_name == 'kms':
            key_service_config.setdefault(
                'key_id', config_data.get('key_id', 'alias/credsmash')
            )

    if table_name:
        storage_service_name = 'dynamodb'
        storage_service_config = {
            'table_name': table_name
        }
    else:
        storage_service_name = config_data.get('storage_service', 'dynamodb')
        storage_service_config = sections.get('credsmash:storage_service:%s' % storage_service_name, {})
        if storage_service_name == 'dynamodb':
            storage_service_config.setdefault(
                'table_name', config_data.get('table_name', 'secret-store')
            )

    algorithm = config_data.get('algorithm', ALGO_AES_CTR)
    algorithm_options = sections.get('credsmash:%s' % algorithm, {})

    set_stream_logger(
        level=config_data.get('log_level', 'INFO')
    )
    env = Environment(
        storage_service_name,
        storage_service_config,
        key_service_name,
        key_service_config,
        algorithm,
        algorithm_options
    )
    ctx.obj = env


@main.command('list')
@click.argument('pattern', required=False)
@click.pass_context
def cmd_list(ctx, pattern=None):
    """
    List all secrets & their versions.
    """
    secrets = credsmash.api.list_secrets(
        ctx.obj.storage_service
    )
    if pattern:
        matched_names = set(fnmatch.filter((secret['name'] for secret in secrets), pattern))
        secrets = [
            secret
            for secret in secrets
            if secret['name'] in matched_names
        ]

    if not secrets:
        return

    max_len = max(len(secret["name"]) for secret in secrets)
    for cred in sorted(secrets, key=operator.itemgetter("name", "version")):
        click.echo(
            "{cred[name]:{l}} -- version {cred[version]:>}".format(l=max_len, cred=cred)
        )


@main.command('delete')
@click.argument('secret_name')
@click.pass_context
def cmd_delete_one(ctx, secret_name):
    """
    Delete every version of a single secret
    """
    credsmash.api.delete_secret(
        ctx.obj.storage_service, secret_name
    )


@main.command('delete-many')
@click.argument('pattern')
@click.pass_context
def cmd_delete_many(ctx, pattern):
    """
    Delete every version of all matching secrets
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.storage_service)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    for secret_name in secret_names:
        credsmash.api.delete_secret(
            ctx.obj.storage_service, secret_name
        )


@main.command('prune')
@click.argument('secret_name')
@click.pass_context
def cmd_prune_one(ctx, secret_name):
    """
    Delete all but the latest version of a single secret
    """
    credsmash.api.prune_secret(
        ctx.obj.storage_service, secret_name
    )


@main.command('prune-many')
@click.argument('pattern')
@click.pass_context
def cmd_prune_many(ctx, pattern):
    """
    Delete all but the latest version of all matching secrets
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.storage_service)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    for secret_name in secret_names:
        credsmash.api.prune_secret(
            ctx.obj.storage_service, secret_name
        )


@main.command('get')
@click.argument('secret_name')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('-f', '--format', 'fmt', default=None)
@click.option('--version', '-v', default=None, type=click.INT)
@click.pass_context
def cmd_get_one(ctx, secret_name, destination, fmt=None, version=None):
    """
    Fetch the latest, or a specific version of a secret
    """
    secret_value = credsmash.api.get_secret(
        ctx.obj.storage_service,
        ctx.obj.key_service,
        secret_name,
        version=version,
    )
    if not fmt:
        fmt = detect_format(destination, default_format='raw')
    write_one(secret_name, secret_value, destination, fmt)


@main.command('get-all')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('-f', '--format', 'fmt', default=None)
@click.pass_context
def cmd_get_all(ctx, destination, fmt):
    """
    Fetch the latest version of all secrets
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.storage_service)
    }
    secrets = {
        secret_name: credsmash.api.get_secret(
            ctx.obj.storage_service,
            ctx.obj.key_service,
            secret_name,
        )
        for secret_name in secret_names
    }
    if not fmt:
        fmt = detect_format(destination, default_format='json')
    write_many(secrets, destination, fmt)


@main.command('find-one')
@click.argument('pattern')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('-f', '--format', 'fmt', default=None)
@click.option('--version', '-v', default=None)
@click.pass_context
def cmd_find_one(ctx, pattern, destination, fmt=None, version=None):
    """
    Find exactly one secret matching <pattern>
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.storage_service)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    if not secret_names:
        raise click.ClickException('No matching secrets found for pattern={0}'.format(pattern))
    if len(secret_names) > 1:
        raise click.ClickException('Too many results ({0}) for pattern={1}'.format(len(secret_names), pattern))

    secret_name = secret_names[0]
    secret_value = credsmash.api.get_secret(
        ctx.obj.storage_service,
        ctx.obj.key_service,
        secret_name,
        version=version,
    )
    if not fmt:
        fmt = detect_format(destination, default_format='raw')
    write_one(secret_name, secret_value, destination, fmt)


@main.command('find-many')
@click.argument('pattern')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('-f', '--format', 'fmt', default=None)
@click.pass_context
def cmd_find_many(ctx, pattern, destination, fmt=None):
    """
    Find all secrets matching <pattern>
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.storage_service)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    secrets = {
        secret_name: credsmash.api.get_secret(
            ctx.obj.storage_service,
            ctx.obj.key_service,
            secret_name,
        )
        for secret_name in secret_names
    }
    if not fmt:
        fmt = detect_format(destination, default_format='json')
    write_many(secrets, destination, fmt)


@main.command('put')
@click.argument('secret_name')
@click.argument('source', type=click.File('rb'))
@click.option('-f', '--format', 'fmt', default=None)
@click.option('--version', '-v', default=None, type=click.INT)
@click.option('--compare/--no-compare', default=True,
              help="Compare with the latest value, and skip if unchanged.")
@click.pass_context
def cmd_put_one(ctx, secret_name, source, fmt=None, version=None, compare=True):
    """
    Store a secret
    """
    if not fmt:
        fmt = detect_format(source, default_format='raw')
    secret_value = read_one(secret_name, source, fmt)

    stored_version = credsmash.api.put_secret(
        ctx.obj.storage_service,
        ctx.obj.key_service,
        secret_name,
        secret_value,
        version=version,
        compare=compare,
        algorithm=ctx.obj.algorithm,
        **ctx.obj.algorithm_options
    )
    logger.info(
        'Stored {0} @ version {1}'.format(secret_name, stored_version)
    )


@main.command('put-many')
@click.argument('source', type=click.File('rb'))
@click.option('-f', '--format', 'fmt', default=None)
@click.option('--compare/--no-compare', default=True,
              help="Compare with the latest value, and skip if unchanged.")
@click.pass_context
def cmd_put_many(ctx, source, fmt, compare=True):
    """
    Store many secrets
    """
    if not fmt:
        fmt = detect_format(source, default_format='json')
    secrets = read_many(source, fmt)

    for secret_name, secret_value in secrets.items():
        stored_version = credsmash.api.put_secret(
            ctx.obj.storage_service,
            ctx.obj.key_service,
            secret_name,
            secret_value,
            version=None,
            compare=compare,
            algorithm=ctx.obj.algorithm,
            **ctx.obj.algorithm_options
        )
        logger.info('Stored {0} @ version {1}'.format(secret_name, stored_version))
    logger.debug('Stored {0} secrets'.format(len(secrets)))


# Load any extra CLI's
for ep in pkg_resources.iter_entry_points('credsmash.cli'):
    try:
        ep.load()
    except ImportError:
        pass
