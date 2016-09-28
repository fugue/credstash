from setuptools import setup, find_packages
import codecs
from os.path import dirname, join

here = dirname(__file__)


def read_file(*parts):
    return codecs.open(join(here, *parts), 'r').read()


setup(
    name='credsmash',
    version=read_file('credsmash', 'VERSION'),
    packages=find_packages(exclude=('tests',)),
    description='A utility for managing secrets in the cloud using AWS KMS and DynamoDB',
    license='Apache2',
    url='https://github.com/3stack-software/credsmash',
    package_data={
        'credsmash': ['VERSION']
    },
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
    ],
    install_requires=[
        'cryptography~=1.5',
        'boto3>=1.1.1',
        'click>=6.6',
        'six'
    ],
    extras_require={
        'yaml': ['PyYAML>=3.10'],
        'templates': ['jinja2'],
    },
    entry_points={
        'console_scripts': [
            'credsmash = credsmash.cli:main'
        ]
    }
)
