from setuptools import setup, find_packages

setup(
    name='credstash',
    version='1.0',
    description='A utility for managing secrets in the cloud using AWS KMS and DynamoDB',
    license='Apache2',
    url='https://github.com/LuminalOSS/credstash',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Topic :: System :: Utilities'
        ],
    install_requires=['boto>=2.38.0', 'pycrypto>=2.6.1'],
    scripts=['credstash.py'],
    entry_points={
        'console_scripts': [
            'credstash = credstash:main'
            ]
        }
    )
