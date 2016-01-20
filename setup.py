from setuptools import setup, find_packages

setup(
    name='credstash',
    version='1.9.1',
    description='A utility for managing secrets in the cloud using AWS KMS and DynamoDB',
    license='Apache2',
    url='https://github.com/LuminalOSS/credstash',
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
    ],
    install_requires=['pycrypto>=2.6.1', 'boto3>=1.1.1'],
    extras_require={'YAML': ['PyYAML>=3.10']},
    scripts=['credstash.py'],
    py_modules=['credstash'],
    entry_points={
        'console_scripts': [
            'credstash = credstash:main'
        ]
    }
)
