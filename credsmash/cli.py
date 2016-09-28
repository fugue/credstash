from __future__ import absolute_import, division, print_function

import fnmatch
import logging
import operator
import sys
import os
import codecs

import boto3
import click
import credsmash.api
from credsmash.util import set_stream_logger, \
    DEFAULT_DIGEST, HASHING_ALGORITHMS, \
    parse_config, read_one, read_many, write_one, write_many

logger = logging.getLogger(__name__)


class Environment(object):
    def __init__(self, table_name, key_id):
        self.table_name = table_name
        self.key_id = key_id
        self._session = None
        self._dynamodb = None
        self._kms = None

    @property
    def session(self):
        if self._session is None:
           self._session = boto3.Session()
        return self._session

    @property
    def dynamodb(self):
        if self._dynamodb is None:
            self._dynamodb = self.session.resource('dynamodb')
        return self._dynamodb

    @property
    def kms(self):
        if self._kms is None:
            self._kms = self.session.client('kms')
        return self._kms

    @property
    def secrets_table(self):
        return self.dynamodb.Table(self.table_name)

    def __repr__(self):
        return 'Environment(table_name=%r,key_id=%r)' % (self.table_name, self.key_id)


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
@click.pass_context
def main(ctx, config, table_name, key_id):
    config_data = {}
    if os.path.exists(config):
        with codecs.open(config, 'r') as config_fp:
            config_data = parse_config(config_fp).get('credsmash', {})
    config_data.setdefault('table_name', 'secret-store')
    if table_name:
        config_data['table_name'] = table_name
    config_data.setdefault('key_id', 'alias/credsmash')
    if key_id:
        config_data['key_id'] = key_id

    set_stream_logger(
        level=config_data.get('log_level', 'INFO')
    )
    env = Environment(
        config_data['table_name'], config_data['key_id'],
    )
    logger.debug('environment=%r', env)
    ctx.obj = env


@main.command('list')
@click.argument('pattern', required=False)
@click.pass_context
def cmd_list(ctx, pattern=None):
    """
    List all secrets & their versions.
    """
    secrets = credsmash.api.list_secrets(
        ctx.obj.secrets_table
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
        logger.info(
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
        ctx.obj.secrets_table, secret_name
    )


@main.command('delete-many')
@click.argument('pattern')
@click.pass_context
def cmd_delete_many(ctx, pattern):
    """
    Delete every version of all matching secrets
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.secrets_table)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    for secret_name in secret_names:
        credsmash.api.delete_secret(
            ctx.obj.secrets_table, secret_name
        )


@main.command('prune')
@click.argument('secret_name')
@click.pass_context
def cmd_prune_one(ctx, secret_name):
    """
    Delete all but the latest version of a single secret
    """
    credsmash.api.prune_secret(
        ctx.obj.secrets_table, secret_name
    )


@main.command('prune-many')
@click.argument('pattern')
@click.pass_context
def cmd_prune_many(ctx, pattern):
    """
    Delete all but the latest version of all matching secrets
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.secrets_table)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    for secret_name in secret_names:
        credsmash.api.prune_secret(
            ctx.obj.secrets_table, secret_name
        )


@main.command('get')
@click.argument('secret_name')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('--format', '-f', default='raw')
@click.option('--version', '-v', default=None, type=click.INT)
@click.option('--context', type=(unicode, unicode), multiple=True)
@click.pass_context
def cmd_get_one(ctx, secret_name, destination, format='raw', version=None, context=tuple()):
    """
    Fetch the latest, or a specific version of a secret
    """
    secret_value = credsmash.api.get_secret(
        ctx.obj.secrets_table,
        ctx.obj.kms,
        secret_name,
        version=version,
        context=dict(context)
    )
    write_one(secret_name, secret_value, destination, format)


@main.command('get-all')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('--format', '-f', default='json')
@click.option('--context', type=(unicode, unicode), multiple=True)
@click.pass_context
def cmd_get_all(ctx, destination, format='json', context=tuple()):
    """
    Fetch the latest version of all secrets
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.secrets_table)
    }
    secrets = {
        secret_name: credsmash.api.get_secret(
            ctx.obj.secrets_table,
            ctx.obj.kms,
            secret_name,
            context=dict(context)
        )
        for secret_name in secret_names
    }
    write_many(secrets, destination, format)


@main.command('find-one')
@click.argument('pattern')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('--format', '-f', default='raw')
@click.option('--version', '-v', default=None)
@click.option('--context', type=(unicode, unicode), multiple=True)
@click.pass_context
def cmd_find_one(ctx, pattern, destination, format='raw', version=None, context=tuple()):
    """
    Find exactly one secret matching <pattern>
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.secrets_table)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    if not secret_names:
        raise click.ClickException('No matching secrets found for pattern={0}'.format(pattern))
    if len(secret_names) > 1:
        raise click.ClickException('Too many results ({0}) for pattern={1}'.format(len(secret_names), pattern))

    secret_name = secret_names[0]
    secret_value = credsmash.api.get_secret(
        ctx.obj.secrets_table,
        ctx.obj.kms,
        secret_name,
        version=version,
        context=dict(context)
    )
    write_one(secret_name, secret_value, destination, format)


@main.command('find-many')
@click.argument('pattern')
@click.argument('destination', type=click.File('wb'), required=False, default=sys.stdout)
@click.option('--format', '-f', default='json')
@click.option('--context', type=(unicode, unicode), multiple=True)
@click.pass_context
def cmd_find_many(ctx, pattern, destination, format='json', context=tuple()):
    """
    Find all secrets matching <pattern>
    """
    secret_names = {
        x["name"] for x in credsmash.api.list_secrets(ctx.obj.secrets_table)
    }
    secret_names = fnmatch.filter(secret_names, pattern)
    secrets = {
        secret_name: credsmash.api.get_secret(
            ctx.obj.secrets_table,
            ctx.obj.kms,
            secret_name,
            context=dict(context)
        )
        for secret_name in secret_names
    }
    write_many(secrets, destination, format)


@main.command('put')
@click.argument('secret_name')
@click.argument('source', type=click.File('rb'))
@click.option('--format', '-f', default='raw')
@click.option('--version', '-v', default=None, type=click.INT)
@click.option('--context', type=(unicode, unicode), multiple=True)
@click.option('--digest', default=DEFAULT_DIGEST, type=click.Choice(HASHING_ALGORITHMS),
              help="the hashing algorithm used to "
                   "to encrypt the data. Defaults to SHA256")
@click.pass_context
def cmd_put_one(ctx, secret_name, source, format='raw', version=None, context=tuple(), digest=DEFAULT_DIGEST):
    """
    Store a secret
    """
    secret_value = read_one(secret_name, source, format)

    if version is None:
        version = 1 + credsmash.api.get_highest_version(
            ctx.obj.secrets_table, secret_name
        )

    credsmash.api.put_secret(
        ctx.obj.secrets_table,
        ctx.obj.kms,
        ctx.obj.key_id,
        secret_name,
        secret_value,
        version,
        context=dict(context),
        digest=digest
    )
    logger.info(
        'Stored {0} @ version {1}'.format(secret_name, version)
    )


@main.command('put-many')
@click.argument('source', type=click.File('rb'))
@click.option('--format', '-f', default='json')
@click.option('--context', type=(unicode, unicode), multiple=True)
@click.option('--digest', default=DEFAULT_DIGEST)
@click.pass_context
def cmd_put_many(ctx, source, format='json', context=tuple(), digest=DEFAULT_DIGEST):
    """
    Store many secrets
    """
    secrets = read_many(source, format)

    for secret_name, secret_value in secrets.items():
        version = 1 + credsmash.api.get_highest_version(
            ctx.obj.secrets_table, secret_name
        )
        credsmash.api.put_secret(
            ctx.obj.secrets_table,
            ctx.obj.kms,
            ctx.obj.key_id,
            secret_name,
            secret_value,
            version,
            context=dict(context),
            digest=digest
        )
        logger.info('Stored {0} @ version {1}'.format(secret_name, version))
    logger.debug('Stored {0} secrets'.format(len(secrets)))


@main.command('setup')
@click.option('--read-capacity', type=click.INT, default=1)
@click.option('--write-capacity', type=click.INT, default=1)
@click.pass_context
def cmd_setup(ctx, read_capacity, write_capacity):
    """
    Setup the credential table in AWS DynamoDB
    """
    credsmash.api.create_secrets_table(
        ctx.obj.dynamodb, ctx.obj.table_name,
        read_capacity, write_capacity
    )
