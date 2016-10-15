from __future__ import absolute_import, division, print_function

import sys

import boto3
import click
import pkg_resources
import six

from credsmash import get_session
from credsmash.util import set_stream_logger, detect_format, \
    read_one, read_many, write_one, write_many


@click.group()
@click.option('--config', '-c',
              type=click.Path(resolve_path=True),
              default=None)
@click.option('--table-name', '-t', default=None,
              help="DynamoDB table to use for "
                   "credential storage")
@click.option('--key-id', '-k', default=None,
              help="the KMS key-id of the master key "
                   "to use. See the README for more "
                   "information. Defaults to alias/credsmash")
@click.option('--context', type=(six.text_type, six.text_type), multiple=True,
              help="the KMS encryption context to use."
                   "Only works if --key-id is passed.")
@click.pass_context
def main(ctx, config, table_name, key_id, context=None):
    ctx.obj = get_session(
        config=config,
        table_name=table_name,
        key_id=key_id,
        context=context
    )
    set_stream_logger(
        level=ctx.obj.log_level
    )


@main.command('list')
@click.argument('pattern', required=False)
@click.pass_context
def cmd_list(ctx, pattern=None):
    """
    List all secrets & their versions.
    """
    if pattern:
        secrets = ctx.obj.list_filtered(pattern)
    else:
        secrets = ctx.obj.list_all()

    if not secrets:
        return

    max_len = max(len(secret_name) for secret_name, _ in secrets)
    for secret_name, version in sorted(secrets):
        click.echo("{0:{l}} -- version {1:>}".format(
                   secret_name, version, l=max_len))


@main.command('delete')
@click.argument('secret_name')
@click.pass_context
def cmd_delete_one(ctx, secret_name):
    """
    Delete every record of a secret
    """
    ctx.obj.delete_one(secret_name)


@main.command('delete-many')
@click.argument('pattern')
@click.pass_context
def cmd_delete_many(ctx, pattern):
    """
    Delete every record of all matching secrets
    """
    ctx.obj.delete_many(pattern)


@main.command('prune')
@click.argument('secret_name')
@click.pass_context
def cmd_prune_one(ctx, secret_name):
    """
    Delete all but the latest version of a single secret
    """
    ctx.obj.prune_one(secret_name)


@main.command('prune-many')
@click.argument('pattern')
@click.pass_context
def cmd_prune_many(ctx, pattern):
    """
    Delete all but the latest version of all matching secrets
    """
    ctx.obj.prune_many(pattern)


@main.command('get')
@click.argument('secret_name')
@click.argument('destination', type=click.File('wb'), required=False, default='-')
@click.option('-f', '--format', 'fmt', default=None)
@click.option('--version', '-v', default=None, type=click.INT)
@click.pass_context
def cmd_get_one(ctx, secret_name, destination, fmt=None, version=None):
    """
    Fetch the latest, or a specific version of a secret
    """
    secret_value = ctx.obj.get_one(
        secret_name,
        version=version,
    )
    if not fmt:
        fmt = detect_format(destination, default_format='raw')
    write_one(secret_name, secret_value, destination, fmt)


@main.command('get-all')
@click.argument('destination', type=click.File('wb'), required=False, default='-')
@click.option('-f', '--format', 'fmt', default=None)
@click.pass_context
def cmd_get_all(ctx, destination, fmt):
    """
    Fetch the latest version of all secrets
    """
    secrets = ctx.obj.get_all()
    if not fmt:
        fmt = detect_format(destination, default_format='json')
    write_many(secrets, destination, fmt)


@main.command('find-one')
@click.argument('pattern')
@click.argument('destination', type=click.File('wb'), required=False, default='-')
@click.option('-f', '--format', 'fmt', default=None)
@click.option('--version', '-v', default=None)
@click.pass_context
def cmd_find_one(ctx, pattern, destination, fmt=None, version=None):
    """
    Find exactly one secret matching <pattern>
    """
    secret_name, secret_value = ctx.obj.find_one(pattern)
    if not fmt:
        fmt = detect_format(destination, default_format='raw')
    write_one(secret_name, secret_value, destination, fmt)


@main.command('find-many')
@click.argument('pattern')
@click.argument('destination', type=click.File('wb'), required=False, default='-')
@click.option('-f', '--format', 'fmt', default=None)
@click.pass_context
def cmd_find_many(ctx, pattern, destination, fmt=None):
    """
    Find all secrets matching <pattern>
    """
    secrets = ctx.obj.find_many(pattern)
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

    ctx.obj.put_one(
        secret_name,
        secret_value,
        version=version,
        compare=compare,
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
    ctx.obj.put_many(secrets, compare=compare)


# Load any extra CLI's
for ep in pkg_resources.iter_entry_points('credsmash.cli'):
    try:
        ep.load()
    except ImportError:
        pass
