# CredStash

## Quick Installation
1. `pip install credstash`
2. Set up a key called credstash in KMS
3. Make sure you have AWS creds in a place that boto/botocore can read them
4. `credstash setup`


## What is this?
Software systems often need access to some shared credential. For example, your web application needs access to a database password, or an API key for some third party service.

Some organizations build complete credential-management systems, but for most of us, managing these credentials is usually an afterthought. In the best case, people use systems like ansible-vault, which does a pretty good job, but leads to other management issues (like where/how to store the master key). A lot of credential management schemes amount to just SCP'ing a `secrets` file out to the fleet, or in the worst case, burning secrets into the SCM (do a github search on `password`).

CredStash is a very simple, easy to use credential management and distribution system that uses AWS Key Management Service (KMS) for key wrapping and master-key storage, and DynamoDB for credential storage and sharing.

## How does it work?
After you complete the steps in the `Setup` section, you will have an encryption key in KMS (in this README, we will refer to that key as the `master key`), and a credential storage table in DDB.

### Stashing Secrets
Whenever you want to store/share a credential, such as a database password, you simply run `credstash put [credential-name] [credential-value]`. For example, `credstash put myapp.db.prod supersecretpassword1234`. credstash will go to the KMS and generate a unique data encryption key, which itself is encrypted by the master key (this is called key wrapping). credstash will use the data encryption key to encrypt the credential value. It will then store the encrypted credential, along with the wrapped (encrypted) data encryption key in the credential store in DynamoDB.

### Getting Secrets
When you want to fetch the credential, for example as part of the bootstrap process on your web-server, you simply do `credstash get [credential-name]`. For example, `export DB_PASSWORD=$(credstash get myapp.db.prod)`. When you run `get`, credstash will go and fetch the encrypted credential and the wrapped encryption key from the credential store (DynamoDB). It will then send the wrapped encryption key to KMS, where it is decrypted with the master key. credstash then uses the decrypted data encryption key to decrypt the credential. The credential is printed to `stdout`, so you can use it in scripts or assign environment variables to it.

### Controlling and Auditing Secrets
Optionally, you can include any number of [Encryption Context](http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html) key value pairs to associate with the credential. The exact set of encryption context key value pairs that were associated with the credential when it was `put` in DynamoDB must be provided in the `get` request to successfully decrypt the credential. These encryption context key value pairs are useful to provide auditing context to the encryption and decryption operations in your CloudTrail logs. They are also useful for constraining access to a given credstash stored credential by using KMS Key Policy conditions and KMS Grant conditions. Doing so allows you to, for example, make sure that your database servers and web-servers can read the web-server DB user password but your database servers can not read your web-servers TLS/SSL certificate's private key. A `put` request with encryption context would look like `credstash put myapp.db.prod supersecretpassword1234 app.tier=db environment=prod`. In order for your web-servers to read that same credential they would execute a `get` call like `export DB_PASSWORD=$(credstash get myapp.db.prod environment=prod app.tier=db)`

### Versioning Secrets
Credentials stored in the credential-store are versioned and immutable. That is, if you `put` a credential called `foo` with a version of `1` and a value of `bar`, then foo version 1 will always have a value of bar, and there is no way in `credstash` to change its value (although you could go fiddle with the bits in DDB, but you shouldn't do that). Credential rotation is handed through versions. Suppose you do `credstash put foo bar`, and then decide later to rotate `foo`, you can put version 2 of `foo` by doing `credstash put foo baz -v `. The next time you do `credstash get foo`, it will return `baz`. You can get specific credential versions as well (with the same `-v` flag). You can fetch a list of all credentials in the credential-store and their versions with the `list` command.

If you use incrementing integer version numbers (for example, `[1, 2, 3, ...]`), then you can use the `-a` flag with the `put` command to automatically increment the version number. However, because of the lexicographical sorting in DynamoDB, `credstash` will left-pad the version representation with zeros (for example, `[001, 025, 103, ...]`, except to 19 characters, enough to handle `sys.maxint` on 64-bit systems).

#### Special Note for Those Using Credstash Auto-Versioning Before December 2015
Prior to December 2015, `credstash` auto-versioned with unpadded integers. This resulted in a sorting error once a key hit ten versions. To ensure support for dates that were not numbers (such as dates, build versions, names, etc.), the lexicographical sorting behavior was retained, but the auto-versioning behavior was changed to left-pad integer representations.

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

See https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs for more information.

## Usage
```
usage: credstash [-h] [-r REGION] [-t TABLE] {delete,get,getall,list,put,setup} ...

A credential/secret storage system

delete
    usage: credstash delete [-h] [-r REGION] [-t TABLE] credential

    positional arguments:
      credential  the name of the credential to delete

get
    usage: credstash get [-h] [-r REGION] [-t TABLE] [-k KEY] [-n] [-v VERSION]
                         credential [context [context ...]]

    positional arguments:
      credential            the name of the credential to get. Using the wildcard
                            character '*' will search for credentials that match
                            the pattern
      context               encryption context key/value pairs associated with the
                            credential in the form of "key=value"

    optional arguments:
      -n, --noline          Don't append newline to returned value (useful in
                            scripts or with binary files)
      -v VERSION, --version VERSION
                            Get a specific version of the credential (defaults to
                            the latest version).

getall
    usage: credstash getall [-h] [-r REGION] [-t TABLE] [-v VERSION] [-f {json,yaml,csv}]
                            [context [context ...]]

    positional arguments:
      context               encryption context key/value pairs associated with the
                            credential in the form of "key=value"

    optional arguments:
      -v VERSION, --version VERSION
                            Get a specific version of the credential (defaults to
                            the latest version).
      -f {json,yaml,csv}, --format {json,yaml,csv}
                            Output format. json(default), yaml or csv.


list
    usage: credstash list [-h] [-r REGION] [-t TABLE]

put
usage: credstash put [-h] [-k KEY] [-v VERSION] [-a]
                     credential value [context [context ...]]

positional arguments:
  credential            the name of the credential to store
  value                 the value of the credential to store or, if beginning
                        with the "@" character, the filename of the file
                        containing the value
  context               encryption context key/value pairs associated with the
                        credential in the form of "key=value"

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     the KMS key-id of the master key to use. See the
                        README for more information. Defaults to
                        alias/credstash
  -v VERSION, --version VERSION
                        Put a specific version of the credential (update the
                        credential; defaults to version `1`).
  -a, --autoversion     Automatically increment the version of the credential
                        to be stored. This option causes the `-v` flag to be
                        ignored. (This option will fail if the currently
                        stored version is not numeric.)

setup
    usage: credstash setup [-h] [-r REGION] [-t TABLE]

optional arguments:
  -r REGION, --region REGION
                        the AWS region in which to operate. If a region is not
                        specified, credstash will use the value of the
                        AWS_DEFAULT_REGION env variable, or if that is not
                        set, us-east-1
  -t TABLE, --table TABLE
                        DynamoDB table to use for credential storage
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
You can read secrets from credstash with the get or getall actions by either using KMS Key Grants, KMS Key Policies, or IAM Policies. If you are using IAM Policies, the following IAM permissions are the minimum required to be able to put or read secrets:
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

## Security Notes
Any IAM principal who can get items from the credential store DDB table, and can call KMS.Decrypt, can read stored credentials.

The target deployment-story for `credstash` is an EC2 instance running with an IAM role that has permissions to read the credential store and use the master key. Since IAM role credentials are vended by the instance metadata service, by default, any user on the system can fetch creds and use them to retrieve credentials. That means that by default, the instance boundary is the security boundary for this system. If you are worried about unauthorized users on your instance, you should take steps to secure access to the Instance Metadata Service (for example, use iptables to block connections to 169.254.169.254 except for privileged users). Also, because credstash is written in python, if an attacker can dump the memory of the credstash process, they may be able to recover credentials. This is a known issue, but again, in the target deployment case, the security boundary is assumed to be the instance boundary.

## Frequently Asked Questions (FAQ)

### 1. Where is the master key stored?
The master key is stored in AWS Key Management Service (KMS), where it is stored in secure HSM-backed storage. The Master Key never leaves the KMS service.

### 2. How is credential rotation handled?
Every credential in the store has a version number. Whenever you want to a credential to a new value, you have to do a `put` with a new credential version. For example, if you have `foo` version 1 in the database, then to update `foo`, you can put version 2. You can either specify the version manually (i.e. `credstash put foo bar -v 2), or you can use the `-a` flag, which will attempt to autoincrement the version number (for example, `credstash put foo baz -a`). Whenever you do a `get` operation, credstash will fetch the most recent (highest version) version of that credential. So, to do credential rotation, simply put a new version of the credential, and clients fetching the credential will get the new version.

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
