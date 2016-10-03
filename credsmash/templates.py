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
from .util import read_many, shell_quote, parse_manifest, detect_format
from .cli import main

logger = logging.getLogger(__name__)


class CachingProxy(object):
    def __init__(self, getter, key_fmt):
        self._getter = getter
        self._key_fmt = key_fmt
        self._data = {}

    def __getitem__(self, key):
        if key not in self._data:
            if isinstance(key, tuple):
                lookup_key = self._key_fmt.format(*key)
            else:
                lookup_key = self._key_fmt.format(key)
            logger.debug('key=%s lookup_key=%s', key, lookup_key)
            res = self._getter(lookup_key)
            self._data[key] = res
            return res
        return self._data[key]


@main.command('render-template')
@click.argument('template', type=click.File(mode='r', encoding='utf-8'))
@click.argument('destination', type=click.File(mode='w', encoding='utf-8'))
@click.option('--obj-name', default='secrets',
              help='The variable/object name provided to the template')
@click.option('--key-fmt', default='{0}',
              help='Re-use templates by tweaking which variable it maps to- '
                   'eg, "dev.{0}" converts {{secrets.potato}} to the secret "dev.potato"')
@click.option('--data-file', type=click.File(mode='rb'),
              help="Source from data file instead of credential store "
                   "(useful for caching/testing)")
@click.option('--data-file-format', default=None)
@click.pass_context
def cmd_render_template(
        ctx, template, destination,
        obj_name='secrets', key_fmt='{0}',
        data_file=None, data_file_format=None
):
    """
    Render a configuration template....
    """
    if data_file:
        if not data_file_format:
            data_file_format = detect_format(data_file, 'json')
        data = read_many(data_file, data_file_format)
        secrets = CachingProxy(lambda key: data[key], key_fmt)
    else:
        secrets = CachingProxy(lambda key: credsmash.api.get_secret(
            ctx.obj.storage_service,
            ctx.obj.key_service,
            key,
        ), key_fmt)

    env = _make_env()
    output = env.from_string(template.read()).render(**{
        obj_name: secrets
    })
    destination.write(output)


@main.command('render-templates')
@click.argument('manifest', type=click.File(mode='r', encoding='utf-8'))
@click.option('--manifest-format', default=None)
@click.option('--obj-name', default='secrets',
              help='The variable/object name provided to the template')
@click.option('--key-fmt', default='{0}',
              help='Re-use templates by tweaking which variable it maps to- '
                   'eg, "dev.{0}" converts {{secrets.potato}} to the secret "dev.potato"')
@click.option('--data-file', type=click.File(mode='rb'),
              help="Source from data file instead of credential store "
                   "(useful for caching/testing)")
@click.option('--data-file-format', default=None)
@click.pass_context
def cmd_render_template(
        ctx, manifest, manifest_format=None,
        obj_name='secrets', key_fmt='{0}',
        data_file=None, data_file_format=None
):
    """
    Render multiple configuration templates - reads from a manifest file.
    """
    if data_file:
        if not data_file_format:
            data_file_format = detect_format(data_file, 'json')
        data = read_many(data_file, data_file_format)
        secrets = CachingProxy(lambda key: data[key], key_fmt)
    else:
        secrets = CachingProxy(lambda key: credsmash.api.get_secret(
            ctx.obj.storage_service,
            ctx.obj.key_service,
            key,
        ), key_fmt)

    env = _make_env()
    if not manifest_format:
        manifest_format = detect_format(manifest, 'json')
    for entry in parse_manifest(manifest, manifest_format):
        with codecs.open(entry['source'], 'r', encoding='utf-8') as template, \
                codecs.open(entry['destination'], 'w', encoding='utf-8') as destination:
            output = env.from_string(template.read()).render(**{
                obj_name: secrets
            })
            destination.write(output)

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
        logger.info('Rendered template="%s" destination="%s"', entry['source'], entry['destination'])


def _make_env():
    env = jinja2.sandbox.SandboxedEnvironment(
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    env.filters['sh'] = shell_quote
    env.filters['jsonify'] = json.dumps
    return env
