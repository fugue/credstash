# CredStash

## Quick Installation
0. (Linux only) Install dependencies 
1. `pip install credstash`
2. Set up a key called credstash in KMS (found in the IAM console)
3. Make sure you have AWS creds in a place that boto/botocore can read them
4. `credstash setup`

### Linux install-time dependencies
Credstash recently moved from PyCrypto to `cryptography`. `cryptography` uses pre-built binary wheels on OSX and Windows, but does not on Linux. That means that you need to install some dependencies if you want to run credstash on linux. 

For Debian and Ubuntu, the following command will ensure that the required dependencies are installed:
```
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```
For Fedora and RHEL-derivatives, the following command will ensure that the required dependencies are installed:
```
$ sudo yum install gcc libffi-devel python-devel openssl-devel
```

In either case, once you've installed the dependencies, you can do `pip install credstash` as usual.

See https://cryptography.io/en/latest/installation/ for more information.


## What is this?
Software systems often need access to some shared credential. For example, your web application needs access to a database password, or an API key for some third party service.

Some organizations build complete credential-management systems, but for most of us, managing these credentials is usually an afterthought. In the best case, people use systems like ansible-vault, which does a pretty good job, but leads to other management issues (like where/how to store the master key). A lot of credential management schemes amount to just SCP'ing a `secrets` file out to the fleet, or in the worst case, burning secrets into the SCM (do a github search on `password`).

CredStash is a very simple, easy to use credential management and distribution system that uses AWS Key Management Service (KMS) for key wrapping and master-key storage, and DynamoDB for credential storage and sharing.

## Compatibility with Other Languages 
A number of great projects exist to provide credstash compatability with other languages. Here are the ones that we know about (feel free to open a pull request if you know of another):

- https://github.com/jessecoyle/jcredstash (Java)
- https://github.com/adorechic/rcredstash (Ruby)
- https://github.com/kdrakon/scala-credstash (Scala)
- https://github.com/gmo/credstash-php (PHP)
- https://github.com/DavidTanner/nodecredstash (Node.js)
- https://github.com/winebarrel/gcredstash (Go)
- https://github.com/Narochno/Narochno.Credstash (C#)
- https://github.com/republicwireless-open/erlcredstash (Erlang)
- https://github.com/psibi/rucredstash (Rust)

## How does it work?
After you complete the steps in the `Setup` section, you will have an encryption key in KMS (in this README, we will refer to that key as the `master key`), and a credential storage table in DDB.

### Stashing Secrets
Whenever you want to store/share a credential, such as a database password, you simply run `credstash put [credential-name] [credential-value]`. For example, `credstash put myapp.db.prod supersecretpassword1234`. credstash will go to the KMS and generate a unique data encryption key, which itself is encrypted by the master key (this is called key wrapping). credstash will use the data encryption key to encrypt the credential value. It will then store the encrypted credential, along with the wrapped (encrypted) data encryption key in the credential store in DynamoDB.

You can also store a credential either by referencing a file or by passing the secret in via `stdin`. To add a secret from a file, instead of passing the secret as an argument pass the filename of the file containing the secret prefixed by the `@` sign. For example, `credstash put myapp.db.prod @secret.txt`. You can also pass the credential via `stdin` by passing the `-` character as the secret argument. For example, `tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1 | credstash put myapp.db.prod -`.

### Getting Secrets
When you want to fetch the credential, for example as part of the bootstrap process on your web-server, you simply do `credstash get [credential-name]`. For example, `export DB_PASSWORD=$(credstash get myapp.db.prod)`. When you run `get`, credstash will go and fetch the encrypted credential and the wrapped encryption key from the credential store (DynamoDB). It will then send the wrapped encryption key to KMS, where it is decrypted with the master key. credstash then uses the decrypted data encryption key to decrypt the credential. The credential is printed to `stdout`, so you can use it in scripts or assign it to environment variables.

### Controlling and Auditing Secrets
Optionally, you can include any number of [Encryption Context](http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html) key value pairs to associate with the credential. The exact set of encryption context key value pairs that were associated with the credential when it was `put` in DynamoDB must be provided in the `get` request to successfully decrypt the credential. These encryption context key value pairs are useful to provide auditing context to the encryption and decryption operations in your CloudTrail logs. They are also useful for constraining access to a given credstash stored credential by using KMS Key Policy conditions and KMS Grant conditions. Doing so allows you to, for example, make sure that your database servers and web-servers can read the web-server DB user password but your database servers can not read your web-servers TLS/SSL certificate's private key. A `put` request with encryption context would look like `credstash put myapp.db.prod supersecretpassword1234 app.tier=db environment=prod`. In order for your web-servers to read that same credential they would execute a `get` call like `export DB_PASSWORD=$(credstash get myapp.db.prod environment=prod app.tier=db)`

### Versioning Secrets
Credentials stored in the credential-store are versioned and immutable. That is, if you `put` a credential called `foo` with a version of `1` and a value of `bar`, then foo version 1 will always have a value of bar, and there is no way in `credstash` to change its value (although you could go fiddle with the bits in DDB, but you shouldn't do that). Credential rotation is handed through versions. Suppose you do `credstash put foo bar`, and then decide later to rotate `foo`, you can put version 2 of `foo` by doing `credstash put foo baz -v `. The next time you do `credstash get foo`, it will return `baz`. You can get specific credential versions as well (with the same `-v` flag). You can fetch a list of all credentials in the credential-store and their versions with the `list` command.

If you use incrementing integer version numbers (for example, `[1, 2, 3, ...]`), then you can use the `-a` flag with the `put` command to automatically increment the version number. However, because of the lexicographical sorting in DynamoDB, `credstash` will left-pad the version representation with zeros (for example, `[001, 025, 103, ...]`, except to 19 characters, enough to handle `sys.maxint` on 64-bit systems).

#### Special Note for Those Using Credstash Auto-Versioning Before December 2015
Prior to December 2015, `credstash` auto-versioned with unpadded integers. This resulted in a sorting error once a key hit ten versions. To ensure support for versions that were not numbers (such as dates, build versions, names, etc.), the lexicographical sorting behavior was retained, but the auto-versioning behavior was changed to left-pad integer representations.

If you've used auto-versioning so far, you should run the `credstash-migrate-autoversion.py` script included in the root of the repository. If you are supplying your own version numbers, you should ensure a lexicographic sort of your versions produces the result you desire.

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

1. Go to the AWS Console and make sure you are in `us-east-1`. If you want to use a key in a different region, you can pass it in using the `--kms-region` argument.
2. Go to the KMS Console
3. Click "Customer managed keys" in the left sidebar
4. Click "Next" to configure a Symmetric key
5. For alias, put "credstash" and click "Next". If you want to use a different name, be sure to pass it to credstash with the `-k` flag. 
6. Decide what IAM principals, if any, you want to be able to manage the key. Click "Next".
6. On the "Key Usage Permissions" screen, pick the IAM users/roles that will be using credstash (you can change your mind later). Click "Next".
7. Review the key policy and click "Finish".
8. Done!

### Setting up credstash
The easiest thing to do is to just run `pip install credstash`. That will download and install credstash and its dependencies (boto and PyCypto). You can also install credstash with optional YAML support by running `pip install credstash[YAML]` instead.

The second easiest thing to do is to do `python setup.py install` in the `credstash` directory.

The python dependencies for credstash are in the `requirements.txt` file. You can install them with `pip install -r requirements.txt`.

In all cases, you will need a C compiler for building `PyCrypto` (you can install `gcc` by doing `apt-get install gcc` or `yum install gcc`).

You will need to have AWS credentials accessible to boto/botocore. The easiest thing to do is to run credstash on an EC2 instance with an IAM role. Alternatively, you can put AWS credentials in the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables. Or, you can put them in a file (see http://boto.readthedocs.org/en/latest/boto_config_tut.html).

You can specify the region in which `credstash` should operate by using the `-r` flag, or by setting the `AWS_DEFAULT_REGION` environment variable. Note that the command line flag takes precedence over the environment variable. If you set neither, then `credstash` will operate against us-east-1.

Once credentials are in place, run `credstash setup`. This will create the DDB table needed for credential storage.

### Working with multiple AWS accounts (profiles)

If you need to work with multiple AWS accounts, an easy thing to do is to set up multiple profiles in your `~/.aws/credentials` file. For example,

```
[dev]
aws_access_key_id = AKIDEXAMPLEASDFASDF
aws_secret_access_key = SKIDEXAMPLE2103429812039423
[prod]
aws_access_key_id= AKIDEXAMPLEASDFASDF
aws_secret_access_key= SKIDEXAMPLE2103429812039423
```

Then, by setting the `AWS_PROFILE` environment variable to the name of the profile, (dev or prod, in this case), you can point credstash at the appropriate account.

For example:
export AWS_PROFILE=dev ( or AWS_PROFILE=prod )

See https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs for more information.

## Usage
```
usage: credstash [-h] [-r REGION] [--kms-region KMS_REGION] [-t TABLE]
                 [--log-level LOG_LEVEL] [--log-file LOG_FILE]
                 [-p PROFILE | -n ARN]
                 {delete,get,getall,keys,list,put,putall,setup} ...

A credential/secret storage system

positional arguments:
  {delete,get,getall,keys,list,put,putall,setup}
                        Try commands like "/Users/Mike/.pyenv/versions/3.6.5/e
                        nvs/rm/bin/credstash get -h" or "/Users/Mike/.pyenv/ve
                        rsions/3.6.5/envs/rm/bin/credstash put --help" to get
                        each sub command's options
    delete              Delete a credential from the store
    get                 Get a credential from the store
    getall              Get all credentials from the store
    keys                List all keys in the store
    list                list credentials and their versions
    put                 Put a credential into the store
    putall              Put credentials from json into the store
    setup               setup the credential store

optional arguments:
  -h, --help            show this help message and exit
  -r REGION, --region REGION
                        the AWS region in which to operate. If a region is not
                        specified, credstash will use the value of the
                        AWS_DEFAULT_REGION env variable, or if that is not
                        set, the value in `~/.aws/config`. As a last resort,
                        it will use us-east-1
  --kms-region KMS_REGION
                        Region the credstash KMS key will be read from,
                        independent of the region the DDB table is in. If not
                        specified, the KMS region will follow the same
                        resolution path as --region. To save the KMS region,
                        use `credstash setup --save-kms-region KMS_REGION`.
                        The value in this argument takes precedence any saved
                        value.
  -t TABLE, --table TABLE
                        DynamoDB table to use for credential storage. If not
                        specified, credstash will use the value of the
                        CREDSTASH_DEFAULT_TABLE env variable, or if that is
                        not set, the value `credential-store` will be used
  --log-level LOG_LEVEL
                        Set the log level, default WARNING
  --log-file LOG_FILE   Set the log output file, default credstash.log. Errors
                        are printed to stderr and stack traces are logged to
                        file
  -p PROFILE, --profile PROFILE
                        Boto config profile to use when connecting to AWS
  -n ARN, --arn ARN     AWS IAM ARN for AssumeRole

delete
    usage: credstash delete [-h] [-r REGION] [-t TABLE] [-p PROFILE | -n ARN] credential

    positional arguments:
      credential  the name of the credential to delete

get
    usage: credstash get [-h] [-n] [-v VERSION] [-f {json,csv,dotenv,yaml}]
                        credential [context [context ...]]

    positional arguments:
      credential            the name of the credential to get. Using the wildcard
                            character '*' will search for credentials that match
                            the pattern
      context               encryption context key/value pairs associated with the
                            credential in the form of "key=value"

    optional arguments:
      -h, --help            show this help message and exit
      -n, --noline          Don't append newline to returned value (useful in
                            scripts or with binary files)
      -v VERSION, --version VERSION
                            Get a specific version of the credential (defaults to
                            the latest version)
      -f {json,csv,dotenv,yaml}, --format {json,csv,dotenv,yaml}
                            Output format. json(default) yaml csv or dotenv.

getall
    usage: credstash getall [-h] [-r REGION] [-t TABLE] [-p PROFILE | -n ARN] [-v VERSION] [-f {json,yaml,csv,dotenv}]
                            [context [context ...]]

    positional arguments:
      context               encryption context key/value pairs associated with the
                            credential in the form of "key=value"

    optional arguments:
      -v VERSION, --version VERSION
                            Get a specific version of the credential (defaults to
                            the latest version).
      -f {json,yaml,csv,dotenv}, --format {json,yaml,csv,dotenv}
                            Output format. json(default), yaml, csv or dotenv.


list
    usage: credstash list [-h] [-r REGION] [-t TABLE] [-p PROFILE | -n ARN]

put
    usage: credstash put [-h] [-k KEY] [-c COMMENT] [-v VERSION] [-a]
                        [-d {SHA,SHA224,SHA256,SHA384,SHA512,MD5}] [-P]
                        credential [value] [context [context ...]]

    positional arguments:
      credential            the name of the credential to store
      value                 the value of the credential to store or, if beginning
                            with the "@" character, the filename of the file
                            containing the value, or pass "-" to read the value
                            from stdin
      context               encryption context key/value pairs associated with the
                            credential in the form of "key=value"

    optional arguments:
      -h, --help            show this help message and exit
      -k KEY, --key KEY     the KMS key-id of the master key to use. See the
                            README for more information. Defaults to
                            alias/credstash
      -c COMMENT, --comment COMMENT
                            Include reference information or a comment about value
                            to be stored.
      -v VERSION, --version VERSION
                            Put a specific version of the credential (update the
                            credential; defaults to version `1`).
      -a, --autoversion     Automatically increment the version of the credential
                            to be stored. This option causes the `-v` flag to be
                            ignored. (This option will fail if the currently
                            stored version is not numeric.)
      -d {SHA,SHA224,SHA256,SHA384,SHA512,MD5}, --digest {SHA,SHA224,SHA256,SHA384,SHA512,MD5}
                            the hashing algorithm used to to encrypt the data.
                            Defaults to SHA256
      -P, --prompt          Prompt for secret


setup
    usage: credstash setup [-h] [--save-kms-region SAVE_KMS_REGION]
                          [--tags [TAGS [TAGS ...]]]

    optional arguments:
      -h, --help            show this help message and exit
      --save-kms-region SAVE_KMS_REGION
                            Save the region the credstash KMS key will be read
                            from, independent of the region the DDB table is in.
                            This value is saved in ~/.credstash
      --tags [TAGS [TAGS ...]]
                            Tags to apply to the Dynamodb Table passed in as a
                            space sparated list of Key=Value
```
## IAM Policies

### Secret Writer
You can put or write secrets to credstash by either using KMS Key Grants, KMS Key Policies, or IAM Policies. If you are using IAM Policies, the following IAM permissions are the minimum required to be able to put or write secrets:
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "kms:GenerateDataKey"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID"
    },
    {
      "Action": [
        "dynamodb:PutItem"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:dynamodb:us-east-1:AWSACCOUNTID:table/credential-store"
    }
  ]
}
```
If you are using Key Policies or Grants, then the `kms:GenerateDataKey` is not required in the policy for the IAM user/group/role. Replace `AWSACCOUNTID` with the account ID for your table, and replace the KEY-GUID with the identifier for your KMS key (which you can find in the KMS console).

### Secret Reader
You can read secrets from credstash with the get or getall actions by either using KMS Key Grants, KMS Key Policies, or IAM Policies. If you are using IAM Policies, the following IAM permissions are the minimum required to be able to get or read secrets:
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "kms:Decrypt"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID"
    },
    {
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:dynamodb:us-east-1:AWSACCOUNTID:table/credential-store"
    }
  ]
}
```
If you are using Key Policies or Grants, then the `kms:Decrypt` is not required in the policy for the IAM user/group/role. Replace `AWSACCOUNTID` with the account ID for your table, and replace the KEY-GUID with the identifier for your KMS key (which you can find in the KMS console). Note that the `dynamodb:Scan` permission is not required if you do not use wildcards in your `get`s.

### Setup Permissions
In order to run `credstash setup`, you will also need to be able to perform the following DDB operations:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dynamodb:CreateTable",
                "dynamodb:DescribeTable"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:dynamodb:us-west-2:<ACCOUNT NUMBER>:table/credential-store"
        },
        {
            "Action": [
                "dynamodb:ListTables"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
```

## Security Notes
Any IAM principal who can get items from the credential store DDB table, and can call KMS.Decrypt, can read stored credentials.

The target deployment-story for `credstash` is an EC2 instance running with an IAM role that has permissions to read the credential store and use the master key. Since IAM role credentials are vended by the instance metadata service, by default, any user on the system can fetch creds and use them to retrieve credentials. That means that by default, the instance boundary is the security boundary for this system. If you are worried about unauthorized users on your instance, you should take steps to secure access to the Instance Metadata Service (for example, use iptables to block connections to 169.254.169.254 except for privileged users). Also, because credstash is written in python, if an attacker can dump the memory of the credstash process, they may be able to recover credentials. This is a known issue, but again, in the target deployment case, the security boundary is assumed to be the instance boundary.

## Developing credstash

### Running the tests

```
python -m unittest discover -v tests "*.py"
```

### Running the integration tests using BATS
1. The integration tests require a working install of credstash. I recommend not using your primary development/production install.
2. Download and install BATS: https://github.com/sstephenson/bats 
3. Run the tests: `bats integration_tests/`

New integration test PRs are welcome!

## Frequently Asked Questions (FAQ)

### 1. Where is the master key stored?
The master key is stored in AWS Key Management Service (KMS), where it is stored in secure HSM-backed storage. The Master Key never leaves the KMS service.

### 2. How is credential rotation handled?
Every credential in the store has a version number. Whenever you want to a credential to a new value, you have to do a `put` with a new credential version. For example, if you have `foo` version 1 in the database, then to update `foo`, you can put version 2. You can either specify the version manually (i.e. `credstash put foo bar -v 2`), or you can use the `-a` flag, which will attempt to autoincrement the version number (for example, `credstash put foo baz -a`). Whenever you do a `get` operation, credstash will fetch the most recent (highest version) version of that credential. So, to do credential rotation, simply put a new version of the credential, and clients fetching the credential will get the new version.

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
