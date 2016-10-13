from __future__ import absolute_import, division, print_function

import codecs
import grp
import json
import logging
import os
import pwd

import click
import jinja2.sandbox

import credsmash.api
from .util import read_many, shell_quote, parse_manifest, detect_format, ItemNotFound
from .cli import main

logger = logging.getLogger(__name__)


class CredsmashProxy(object):
    def __init__(self, key_service, storage_service, key_fmt):
        self._key_service = key_service
        self._storage_service = storage_service
        self._key_fmt = key_fmt
        self._data = {}

    def __getitem__(self, key):
        if key in self._data:
            return self._data[key]

        if isinstance(key, tuple):
            lookup_key = self._key_fmt.format(*key)
        else:
            lookup_key = self._key_fmt.format(key)
        logger.debug('key=%s lookup_key=%s', key, lookup_key)
        res = credsmash.api.get_secret(
            self._storage_service,
            self._key_service,
            key,
        )
        self._data[key] = res
        return res

    def __contains__(self, key):
        try:
            self.__getitem__(key)
            return True
        except ItemNotFound:
            return False


class DictProxy(object):
    def __init__(self, items, key_fmt):
        self._items = items
        self._key_fmt = key_fmt

    def __getitem__(self, key):
        if isinstance(key, tuple):
            lookup_key = self._key_fmt.format(*key)
        else:
            lookup_key = self._key_fmt.format(key)
        return self._items[lookup_key]

    def __contains__(self, key):
        try:
            self.__getitem__(key)
            return True
        except KeyError:
            return False


@main.command('render-template')
@click.argument('template', type=click.File(mode='r', encoding='utf-8'))
@click.argument('destination', type=click.File(mode='w', encoding='utf-8'))
@click.option('--obj-name', default='secrets',
              help='The variable/object name provided to the template')
@click.option('--key-fmt', default='{0}',
              help='Re-use templates by tweaking which variable it maps to- '
                   'eg, "dev.{0}" converts {{secrets.potato}} to the secret "dev.potato"')
@click.option('--template-vars', type=click.File(mode='rb'))
@click.option('--template-vars-format', default=None)
@click.option('--secrets-file', type=click.File(mode='rb'),
              help="Source from a local file instead of credential store "
                   "(useful for caching/testing)")
@click.option('--secrets-file-format', default=None)
@click.pass_context
def cmd_render_template(
        ctx, template, destination,
        obj_name='secrets', key_fmt='{0}',
        template_vars=None, template_vars_format=None,
        secrets_file=None, secrets_file_format=None
):
    """
    Render a configuration template....
    """
    if secrets_file:
        if not secrets_file_format:
            secrets_file_format = detect_format(secrets_file, 'json')
        local_secrets = read_many(secrets_file, secrets_file_format)
        secrets = DictProxy(local_secrets, key_fmt)
    else:
        secrets = CredsmashProxy(
            ctx.obj.storage_service,
            ctx.obj.key_service,
            key_fmt,
        )

    render_args = {}
    if template_vars:
        if not template_vars_format:
            template_vars_format = detect_format(template_vars, 'json')
        render_args = read_many(template_vars, template_vars_format)
    if obj_name in render_args:
        logger.warning('Overwrote %r from template vars with secrets var.', obj_name)
    render_args[obj_name] = secrets

    env = _make_env()
    output = env.from_string(template.read()).render(render_args)
    destination.write(output)


@main.command('render-templates')
@click.argument('manifest', type=click.File(mode='r', encoding='utf-8'))
@click.option('--manifest-format', default=None)
@click.option('--obj-name', default='secrets',
              help='The variable/object name provided to the template')
@click.option('--key-fmt', default='{0}',
              help='Re-use templates by tweaking which variable it maps to- '
                   'eg, "dev.{0}" converts {{secrets.potato}} to the secret "dev.potato"')
@click.option('--template-vars', type=click.File(mode='rb'))
@click.option('--template-vars-format', default=None)
@click.option('--secrets-file', type=click.File(mode='rb'),
              help="Source from a local file instead of credential store "
                   "(useful for caching/testing)")
@click.option('--secrets-file-format', default=None)
@click.pass_context
def cmd_render_template(
        ctx, manifest, manifest_format=None,
        obj_name='secrets', key_fmt='{0}',
        template_vars=None, template_vars_format=None,
        secrets_file=None, secrets_file_format=None
):
    """
    Render multiple configuration templates - reads from a manifest file.
    """
    if secrets_file:
        if not secrets_file_format:
            secrets_file_format = detect_format(secrets_file, 'json')
        local_secrets = read_many(secrets_file, secrets_file_format)
        secrets = DictProxy(local_secrets, key_fmt)
    else:
        secrets = CredsmashProxy(
            ctx.obj.key_service,
            ctx.obj.storage_service,
            key_fmt,
        )

    render_args = {}
    if template_vars:
        if not template_vars_format:
            template_vars_format = detect_format(template_vars, 'json')
        render_args = read_many(template_vars, template_vars_format)
    if obj_name in render_args:
        logger.warning('Overwrote %r from template vars with secrets var.', obj_name)
    render_args[obj_name] = secrets

    env = _make_env()
    if not manifest_format:
        manifest_format = detect_format(manifest, 'json')
    for entry in parse_manifest(manifest, manifest_format):
        if 'source' in entry:
            with codecs.open(entry['source'], 'r', encoding='utf-8') as template:
                output = env.from_string(template.read()).render(render_args)
            # Only open the file after rendering the template
            #  as we truncate the file when opening.
            with codecs.open(entry['destination'], 'w', encoding='utf-8') as destination:
                destination.write(output)
            logger.info('Rendered template="%s" destination="%s"', entry['source'], entry['destination'])
        elif 'secret' in entry:
            output = secrets[entry['secret']]
            with open(entry['destination'], 'wb') as destination:
                destination.write(output)
            logger.info('Wrote secret="%s" destination="%s"', entry['secret'], entry['destination'])
        else:
            raise RuntimeError('Manifest entry must contain a secret or source')

        if 'mode' in entry:
            os.chmod(
                entry['destination'],
                entry['mode']
            )

        if 'owner' in entry and 'group' in entry:
            os.chown(
                entry['destination'],
                pwd.getpwnam(entry['owner']).pw_uid,
                grp.getgrnam(entry['group']).gr_gid
            )


def _make_env():
    env = jinja2.sandbox.SandboxedEnvironment(
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    env.filters['sh'] = shell_quote
    env.filters['jsonify'] = json.dumps
    return env
