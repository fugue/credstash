import codecs
import sys
from os.path import dirname, join

from setuptools import setup, find_packages

needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []

needs_setupext_pip = {'requirements'}.intersection(sys.argv)
setupext_pip = ['setupext-pip~=1.0.5'] if needs_setupext_pip else []

here = dirname(__file__)


def read(*parts):
    return codecs.open(join(here, *parts), 'r').read()


def find_version(*file_paths):
    version = read(*file_paths).strip()
    if version == '':
        raise RuntimeError('No version found')
    return version


def read_markdown(*file_paths):
    try:
        import pandoc.core
        doc = pandoc.core.Document()
        doc.markdown = read(*file_paths)
        return doc.rst
    except ImportError:
        return ''


setup(
    name='credsmash',
    version=find_version('credsmash', 'VERSION'),

    maintainer="Nathan Muir",
    maintainer_email="ndmuir@gmail.com",

    url='https://github.com/3stack-software/credsmash',

    license='Apache2',
    description='A utility for managing secrets in the cloud using AWS KMS and DynamoDB',
    long_description=read_markdown('README.md'),

    packages=find_packages(exclude=('tests',)),

    package_data={
        'credsmash': ['VERSION']
    },

    setup_requires=[] + pytest_runner + setupext_pip,
    install_requires=[
        'cryptography~=1.5',
        'boto3>=1.1.1',
        'click>=6.6',
        'six'
    ],
    tests_require=[
        'pytest',
    ],
    extras_require={
        'yaml': ['PyYAML>=3.10'],
        'templates': ['jinja2'],
        'documentation': ['pyandoc'],
    },
    entry_points={
        'console_scripts': [
            'credsmash = credsmash.cli:main'
        ],
        'credsmash.key_service': [
            'kms = credsmash.kms_key_service:KmsKeyService',
        ],
        'credsmash.storage_service': [
            'dynamodb = credsmash.dynamodb_storage_service:DynamoDbStorageService',
        ],
        'credsmash.cli': [
            'templates = credsmash.templates',
            'dynamodb = credsmash.cli_dynamodb'
        ]
    },

    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
)
