# CredStash

## Quick Installation
`pip install credstash`
Follow the instructions below for setting up a key in KMS.
Then, just do `credstash setup` and you're off.

## What is this?
Software systems often need access to some shared credential. For example, your web application needs access to a database password, or an API key for some third party service.

Some organizations build complete credential-management systems, but for most of us, managing these credentials is usually an afterthought. In the best case, people use systems like ansible-vault, which does a pretty good job, but leads to other management issues (like where/how to store the master key). A lot of credential management schemes amount to just SCP'ing a `secrets` file out to the fleet, or in the worst case, burning secrets into the SCM (do a github search on `password`).

CredStash is a very simple, easy to use credential management and distribution system that uses AWS Key Management Service (KMS) for key wrapping and master-key storage, and DynamoDB for credential storage and sharing.

## How does it work?
After you complete the steps in the `Setup` section, you will have an encryption key in KMS (in this README, we will refer to that key as the `master key`), and a credential storage table in DDB.

Whenever you want to store/share a credential, such as a database password, you simply run `credstash put [credential-name] [credential-value]`. For example, `credstash put myapp.db.prod supersecretpassword1234`. credstash will go to the KMS and generate a unique data encryption key, which itself is encrypted by the master key (this is called key wrapping). credstash will use the data encryption key to encrypt the credential value. It will then store the encrypted credential, along with the wrapped (encrypted) data encryption key in the credential store in DynamoDB.

When you want to fetch the credential, for example as part of the bootstrap process on your web-server, you simply do `credstash get [credential-name]`. For example, `export DB_PASSWORD=$(credstash get myapp.db.prod)`. When you run `get`, credstash will go and fetch the encrypted credential and the wrapped encryption key from the credential store (DynamoDB). It will then send the wrapped encryption key to KMS, where it is decrypted with the master key. credstash then uses the decrypted data encryption key to decrypt the credential. The credential is printed to `stdout`, so you can use it in scripts or assign environment variables to it.

Credentials stored in the credential-store are versioned and immutable. That is, if you `put` a credential called `foo` with a version of `1` and a value of `bar`, then foo version 1 will always have a value of bar, and there is no way in `credstash` to change its value (although you could go fiddle with the bits in DDB, but you shouldn't do that). Credential rotation is handed through versions. Suppose you do `credstash put foo bar`, and then decide later to rotate `foo`, you can put version 2 of `foo` by doing `credstash put foo baz -v `. The next time you do `credstash get foo`, it will return `baz`. You can get specific credential versions as well (with the same `-v` flag). You can fetch a list of all credentials in the credential-store and their versions with the `list` command.

## Dependencies
credstash uses the following AWS services:
* AWS Key Management Service (KMS) - for master key management and key wrapping
* AWS Identity and Access Management - for access control
* Amazon DynamoDB - for credential storage

## Setup
### tl;dr
1. Set up a key called `credstash` in KMS
2. Install credstash's python dependencies (or just use pip)
3. Make sure you have AWS creds in a place that boto/botocore can read them
4. Run `credstash setup`

### Setting up KMS
`credstash` will not currently set up your KMS master key. To create a KMS master key,

1. Go to the AWS console
2. Go to the IAM console/tab
3. Click "Encryption Keys" in the left
4. Click "Create Key". For alias, put "credstash". If you want to use a different name, be sure to pass it to credstash with the `-k` flag
5. Decide what IAM principals you want to be able to manage the key
6. On the "Key Usage Permissions" screen, pick the IAM users/roles that will be using credstash (you can change your mind later)
7. Done!

### Setting up credstash
The easiest thing to do is to just run `pip install credstash`. That will download and install credstash and its dependencies (boto and PyCypto).

The second easiest thing to do is to do `python setup.py install` in the `credstash` directory.

The python dependencies for credstash are in the `requirements.txt` file. You can install them with `pip install -r requirements.txt`.

In all cases, you will need a C compiler for building `PyCrypto` (you can install `gcc` by doing `apt-get install gcc` or `yum install gcc`).

You will need to have AWS credentials accessible to boto/botocore. The easiest thing to do is to run credstash on an EC2 instance with an IAM role. Alternatively, you can put AWS credentials in the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables. Or, you can put them in a file (see http://boto.readthedocs.org/en/latest/boto_config_tut.html).

Once credentials are in place, run `credstash setup`. This will create the DDB table needed for credential storage.

## Usage
```
usage: credstash.py [-h] [-i INFILE] [-k KEY] [-r REGION] [-v VERSION]
                    {get,list,put,setup} [credential] [value]

A credential/secret storage system

positional arguments:
  {get,list,put,setup}  Put or Get a credential from the store, list
                        credentials and their versions, or setup the
                        credential store
  credential            the name of the credential to store/get
  value                 the value of the credential to put (ignored if action
                        is 'get')

optional arguments:
  -h, --help            show this help message and exit
  -i INFILE, --infile INFILE
                        store the contents of `infile` rather than provide a
                        value on the command line
  -k KEY, --key KEY     the KMS key-id of the master key to use. See the
                        README for more information. Defaults to
                        alias/credstash
  -r REGION, --region REGION
                        the AWS region in which to operate
  -v VERSION, --version VERSION
                        If doing a `put`, put a specific version of the
                        credential (update the credential; defaults to version
                        `1`). If doing a `get`, get a specific version of the
                        credential (defaults to the latest version).
```

## Security Notes
Any IAM principal who can get items from the credential store DDB table, and can call KMS.Decrypt, can read stored credentials.

The target deployment-story for `credstash` is an EC2 instance running with an IAM role that has permissions to read the credential store and use the master key. Since IAM role credentials are vended by the instance metadata service, by default, any user on the system can fetch creds and use them to retrieve credentials. That means that by default, the instance boundary is the security boundary for this system. If you are worried about unauthorized users on your instance, you should take steps to secure access to the Instance Metadata Service (for example, use iptables to block connections to 169.254.169.254 except for privileged users). Also, because credstash is written in python, if an attacker can dump the memory of the credstash process, they may be able to recover credentials. This is a known issue, but again, in the target deployment case, the security boundary is assumed to be the instance boundary.

## Frequently Asked Questions (FAQ)

### 1. Where is the master key stored?
The master key is stored in AWS Key Management Service (KMS), where it is stored in secure HSM-backed storage. The Master Key never leaves the KMS service.

### 2. How is credential rotation handled?
It's not yet. The table in DDB has a `version` field. Right now everything is version 1. Soon, you will be able to update a credential, and fetch specific versions of credentials.

### 3. How much do the AWS services needed to run credstash cost?
tl;dr: If you are using less than 25 reads/sec and 25 writes per second on DDB today, it will cost ~$1/month to use credstash.

The master key in KMS costs $1 per month.

The credential store DDB table uses 1 provisioned read and 1 provisioned write throughput, along with a small amount of actual storage. This falls well below the free tier for DDB (25 reads and 25 writes per second). If you are already a heavy DDB user and exceed the free tier, the credential store table will cost about $0.53 per month (mostly from the write throughput).

If you are using credstash heavily and need to increase the provisioned reads/writes, you may incur additional charges. You can estimate your bill using the AWS Simple Monthly Calculator (http://calculator.s3.amazonaws.com/index.html#s=DYNAMODB).

### 4. Why DynamoDB for the credential store? Why not S3?
DDB fits the application really well. Having very low latency fetches are really nice if credstash is in the critical path of spinning up an application. Being able to turn throughput up or down based on load and requirements are also great things to have in a config management tool. Also, as credstash gets into more complex credential management functions, the query capabilities of DDB get super handy.

That said, S3 support may happen someday.

### 5. Where can I learn more about use cases and context for something like credstash?
Check out this blog post: http://blog.fugue.it/2015-04-21-aws-kms-secrets.html
