from __future__ import absolute_import, division, print_function, unicode_literals

import codecs
import fnmatch
import logging
import os

import pkg_resources

from .crypto import ALGO_AES_CTR, open_secret, seal_secret
from .util import parse_config, ItemNotFound

logger = logging.getLogger(__name__)


class Credsmash(object):
    def __init__(self, storage_service_loader, key_service_loader,
                 algorithm, algorithm_options, log_level):
        self.storage_service_loader = storage_service_loader
        self.key_service_loader = key_service_loader
        self.algorithm = algorithm
        self.algorithm_options = algorithm_options
        self.log_level = log_level

    @property
    def key_service(self):
        return self.key_service_loader.get()

    @property
    def storage_service(self):
        return self.storage_service_loader.get()

    def list_all(self):
        """
        List all secrets & their versions

        :rtype: List[Tuple[text, int]]
        """
        return self.storage_service.list_all()

    def _list_all_names(self):
        """
        :rtype: Set[text]
        """
        return {
            secret_name for secret_name, _ in self.list_all()
        }

    def list_filtered(self, pattern):
        """
        List all secrets & their versions matching <pattern>

        :type pattern: text
        :rtype: List[Tuple[text, int]]
        """
        return [
            (secret_name, version)
            for secret_name, version in self.list_all()
            if fnmatch.fnmatch(secret_name, pattern)
        ]

    def _list_filtered_names(self, pattern):
        """
        :rtype: Set[unicode]
        """
        return {
            secret_name for secret_name, _ in self.list_filtered(pattern)
        }

    def get_one(self, secret_name, version=None):
        """
        Get a secret...
        :type secret_name: text
        :type version: int
        :rtype: bytes
        """
        if version is None:
            version, ciphertext = self.storage_service.get_latest(secret_name)
        else:
            ciphertext = self.storage_service.get_one(secret_name, version)
        if not ciphertext:
            raise ItemNotFound(
                "Item name={0} version={1} couldn't be found.".format(secret_name, version)
            )
        return open_secret(self.key_service, ciphertext, metadata={
            'name': secret_name, 'version': version,
        })

    def get_all(self):
        """
        Get the latest version of all secrets
        :rtype: Dict[text, bytes]
        """
        return {
            secret_name: self.get_one(secret_name)
            for secret_name in self._list_all_names()
        }

    def find_one(self, pattern):
        """
        Find exactly one secret matching <pattern>
        :type pattern: text
        :rtype: Tuple[text, bytes]
        """
        secret_names = self._list_filtered_names(pattern)

        # TODO - Audit/Evaluate the type of errors thrown here
        if not secret_names:
            raise ItemNotFound("Not found pattern={0}".format(pattern))
        if len(secret_names) > 1:
            raise RuntimeError(
                'Found {0} secrets matching pattern={1} matches={2}'.format(
                    len(secret_names), pattern, ",".join(secret_names)
                )
            )

        secret_name = secret_names.pop()
        plaintext = self.get_one(secret_name)
        return secret_name, plaintext

    def find_many(self, pattern):
        """
        Find all secrets matching <pattern>

        :type pattern: text
        :rtype: Dict[text, bytes]
        """
        return {
            secret_name: self.get_one(secret_name)
            for secret_name in self._list_filtered_names(pattern)
        }

    def put_one(self, secret_name, plaintext, version=None, compare=True):
        """
        Store a secret

        :type secret_name: text
        :type plaintext: bytes
        :type version: Optional[int]
        :type compare: bool
        :rtype: int
        :return: The latest version of the secret
        """
        if version is None:
            latest_version, latest_ciphertext = self.storage_service.get_latest(secret_name)
            version = 1
            if latest_ciphertext:
                version += latest_version
                if compare:
                    latest_plaintext = open_secret(
                        self.key_service, latest_ciphertext, metadata={
                            'name': secret_name, 'version': latest_version,
                        }
                    )
                    if plaintext == latest_plaintext:
                        logger.info('"%s" is unchanged from version %d', secret_name, latest_version)
                        return latest_version

        sealed = seal_secret(
            self.key_service,
            plaintext,
            algorithm=self.algorithm,
            binary_type=getattr(self.storage_service, 'binary_type', None),
            metadata={
                'name': secret_name, 'version': version
            },
            **self.algorithm_options
        )

        self.storage_service.put_one(secret_name, version, sealed)
        logger.info('Stored %s @ version %d', secret_name, version)
        return version

    def put_many(self, secrets, compare=True):
        """
        Store many secrets

        :type secrets: Dict[text, bytes]
        :type compare: bool
        """
        for secret_name, plaintext in secrets.items():
            self.put_one(
                secret_name,
                plaintext,
                version=None,
                compare=compare,
            )
        logger.debug('Stored %d secrets', len(secrets))

    def delete_one(self, secret_name):
        """
        Delete every record of a secret
        :type secret_name: text
        """
        secrets = self.storage_service.list_one(secret_name)
        if not secrets:
            logger.info('Not found: %s', secret_name)
            return

        for secret_name, version in secrets:
            logger.info("Deleting %s -- version %s",
                        secret_name, version)
            self.storage_service.delete_one(
                secret_name, version
            )
        logger.info('Deleted %s', secret_name)

    def delete_many(self, pattern):
        """
        Delete every record of all matching secrets
        :type pattern: text
        """
        for secret_name in self._list_filtered_names(pattern):
            self.delete_one(secret_name)

    def prune_one(self, secret_name):
        """
        Delete all but the latest version of a single secret
        :type secret_name: text
        """
        secrets = self.storage_service.list_one(secret_name)
        if not secrets:
            logger.info('Not found: %s', secret_name)
            return

        max_version = max(
            version
            for _, version in secrets
        )

        for secret_name, version in secrets:
            if version == max_version:
                continue
            logger.info("Deleting %s -- version %s",
                        secret_name, version)
            self.storage_service.delete_one(
                secret_name, version
            )
        logger.info('Pruned %s (current version=%d)', secret_name, max_version)

    def prune_many(self, pattern):
        """
        Delete all but the latest version of all matching secrets
        :type pattern: text
        """
        for secret_name in self._list_filtered_names(pattern):
            self.prune_one(secret_name)


def get_session(config=None, table_name=None, key_id=None, context=None):
    if config is None:
        config = os.environ.get('CREDSMASH_CONFIG', '/etc/credsmash.cfg')

    """Creates a new credsmash session."""
    main_section = {}
    sections = {}
    if config and os.path.exists(config):
        with codecs.open(config, 'r') as config_fp:
            sections = parse_config(config_fp)
            main_section = sections.get('credsmash', {})

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
        key_service_name = main_section.get('key_service', 'kms')
        key_service_config = sections.get('credsmash:key_service:%s' % key_service_name, {})
        if key_service_name == 'kms':
            key_service_config.setdefault(
                'key_id', main_section.get('key_id', 'alias/credsmash')
            )

    if table_name:
        storage_service_name = 'dynamodb'
        storage_service_config = {
            'table_name': table_name
        }
    else:
        storage_service_name = main_section.get('storage_service', 'dynamodb')
        storage_service_config = sections.get('credsmash:storage_service:%s' % storage_service_name, {})
        if storage_service_name == 'dynamodb':
            storage_service_config.setdefault(
                'table_name', main_section.get('table_name', 'secret-store')
            )

    algorithm = main_section.get('algorithm', ALGO_AES_CTR)
    algorithm_options = sections.get('credsmash:%s' % algorithm, {})

    return Credsmash(
        EntryPointLoader('credsmash.storage_service', storage_service_name, **storage_service_config),
        EntryPointLoader('credsmash.key_service', key_service_name, **key_service_config),
        algorithm,
        algorithm_options,
        log_level=main_section.get('log_level', 'INFO')
    )


class EntryPointLoader(object):
    def __init__(self, group, name, *args, **kwargs):
        self.group = group
        self.name = name
        self.args = args
        self.kwargs = kwargs
        self._obj = None

    def get(self):
        if not self._obj:
            cls = self.load_entry_point(self.group, self.name)
            self._obj = cls(*self.args, **self.kwargs)
            self.args, self.kwargs = None, None
        return self._obj

    @staticmethod
    def load_entry_point(group, name):
        entry_points = pkg_resources.iter_entry_points(
            group, name
        )
        for entry_point in entry_points:
            return entry_point.load()
        raise RuntimeError('Not found EntryPoint(group={0},name={1})'.format(group, name))
