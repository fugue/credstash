# Cred*Smash*

This is a fork of [credstash](https://github.com/fugue/credstash), to add 
some utilities I find useful, see `HISTORY.md` for details.

## Quick Installation
1. `pip install credsmash[yaml, templates]`
2. Set up a key called `credsmash` in KMS
3. Make sure you have AWS creds in a place that boto/botocore can read 
   them (eg, [Use environment `AWS_CONFIG_FILE`](http://boto3.readthedocs.io/en/latest/guide/configuration.html#environment-variables))
4. `credsmash setup-dynamodb`


## What is this?
Software systems often need access to some shared credential. For example, 
your web application needs access to a database password, or an API key for some 
third party service.

Some organizations build complete credential-management systems, but for most of us, 
managing these credentials is usually an afterthought. In the best case, people use 
systems like ansible-vault, which does a pretty good job, but leads to other management 
issues (like where/how to store the master key). A lot of credential management schemes 
amount to just SCP'ing a `secrets` file out to the fleet, or in the worst case, burning 
secrets into the SCM (do a github search on `password`).

CredSmash is a very simple, easy to use credential management and distribution system 
that uses AWS Key Management Service (KMS) for key wrapping and master-key storage, 
and DynamoDB for credential storage and sharing.

## How does it work?
After you complete the steps in the `Setup` section, you will have an encryption key 
in KMS (in this README, we will refer to that key as the `master key`), and a credential
storage table in DDB.

### Stashing Secrets
Whenever you want to store/share a credential, such as a database password, you simply 
run `echo [credential-value] | credsmash put [credential-name] -`. 
For example, `echo 'supersecretpassword1234' | credsmash put myapp.db.prod -`. credsmash will
go to the KMS and generate a unique data encryption key, which itself is encrypted by the
master key (this is called key wrapping). credsmash will use the data encryption key to
encrypt the credential value. It will then store the encrypted credential, along with the 
wrapped (encrypted) data encryption key in the credential store in DynamoDB.

### Getting Secrets
When you want to fetch the credential, for example as part of the bootstrap process on 
your web-server, you simply do `credsmash get [credential-name]`. For example, 
`export DB_PASSWORD=$(credsmash get myapp.db.prod)`. When you run `get`, 
credsmash will go and fetch the encrypted credential and the wrapped encryption 
key from the credential store (DynamoDB). It will then send the wrapped encryption key to 
KMS, where it is decrypted with the master key. credsmash then uses the decrypted data 
encryption key to decrypt the credential. The credential is printed to `stdout`, so you 
can use it in scripts or assign it to environment variables.

### Controlling and Auditing Secrets
Optionally, you can include any number of [Encryption Context](http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html)
key value pairs to associate with the credential. The exact set of encryption context 
key value pairs that were associated with the credential when it was `put` in DynamoDB 
must be provided in the `get` request to successfully decrypt the credential. These 
encryption context key value pairs are useful to provide auditing context to the encryption
and decryption operations in your CloudTrail logs. They are also useful for constraining 
access to a given credsmash stored credential by using KMS Key Policy conditions and KMS 
Grant conditions. Doing so allows you to, for example, make sure that your database servers 
and web-servers can read the web-server DB user password but your database servers can not 
read your web-servers TLS/SSL certificate's private key. A `put` request with encryption 
context would look like 
`echo 'supersecretpassword1234' | credsmash put myapp.db.prod - --context app.tier db --context environment prod`. 
In order for your web-servers to read that same credential they would execute a `get` call 
like `export DB_PASSWORD=$(credsmash get myapp.db.prod  --context environment prod --context app.tier db)`

### Versioning Secrets
Credentials stored in the credential-store are versioned and immutable. That is, if 
you `put` a credential called `foo` with a version of `1` and a value of `bar`, 
then foo version 1 will always have a value of bar, and there is no way in `credsmash` to 
change its value (although you could go fiddle with the bits in DDB, but you shouldn't do that). 
Credential rotation is handed through versions. Suppose you do `echo 'bar' | credsmash put foo -`, and 
then decide later to rotate `foo`, you can put version 2 of `foo` by doing 
`echo 'baz' | credsmash put foo - -v 2 `. 
The next time you do `credsmash get foo`, it will return `baz`. You can get specific credential versions
as well (with the same `-v` flag). You can fetch a list of all credentials in the 
credential-store and their versions with the `list` command.

If you use incrementing integer version numbers (for example, `[1, 2, 3, ...]`), then you can 
simply skip the `-v` flag with the `put` command to automatically increment the version number. 
However, because of the lexicographical sorting in DynamoDB, `credsmash` will left-pad 
the version representation with zeros (for example, `[001, 025, 103, ...]`, except to 19 characters,
enough to handle `sys.maxint` on 64-bit systems).

## Dependencies
credsmash uses the following AWS services:
* AWS Key Management Service (KMS) - for master key management and key wrapping
* AWS Identity and Access Management - for access control
* Amazon DynamoDB - for credential storage

## Setup
### tl;dr
1. Set up a key called `credsmash` in KMS
2. `pip install credsmash`
3. Make sure you have AWS creds in a place that boto/botocore can read them
4. Run `credsmash setup-dynamodb`

### Setting up KMS
`credsmash` will not currently set up your KMS master key. To create a KMS master key,

1. Go to the AWS console
2. Go to the IAM console/tab
3. Click "Encryption Keys" in the left
4. Click "Create Key". For alias, put "credsmash". If you want to use a different name, be sure to pass it to credsmash with the `-k` flag
5. Decide what IAM principals you want to be able to manage the key
6. On the "Key Usage Permissions" screen, pick the IAM users/roles that will be using credsmash (you can change your mind later)
7. Done!

### Setting up credsmash
The easiest thing to do is to just run `pip install credsmash`. That will download and install credsmash and its dependencies (boto and PyCypto).

The second easiest thing to do is to do `python setup.py install` in the `credsmash` directory.

The python dependencies for credsmash are in the `requirements.txt` file. You can install them with `pip install -r requirements.txt`.

In all cases, you will need a C compiler for building `PyCrypto` (you can install `gcc` by doing `apt-get install gcc` or `yum install gcc`).

You will need to have AWS credentials accessible to boto/botocore. The easiest thing to do is to run credsmash on an EC2 instance with an IAM role. Alternatively, you can put AWS credentials in the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables. Or, you can put them in a file (see http://boto.readthedocs.org/en/latest/boto_config_tut.html).

You can specify the region in which `credsmash` should operate by using the `-r` flag, or by setting the `AWS_DEFAULT_REGION` environment variable. Note that the command line flag takes precedence over the environment variable. If you set neither, then `credsmash` will operate against us-east-1.

Once credentials are in place, run `credsmash setup-dynamodb`. This will create the DDB table needed for credential storage.

### Working with multiple AWS accounts (profiles)

If you need to work with multiple AWS accounts, an easy thing to do is to set up multiple profiles in 
your `~/.aws/credentials` file. For example,

```
[dev]
aws_access_key_id = AKIDEXAMPLEASDFASDF
aws_secret_access_key = SKIDEXAMPLE2103429812039423
[prod]
aws_access_key_id= AKIDEXAMPLEASDFASDF
aws_secret_access_key= SKIDEXAMPLE2103429812039423
```

Then, by setting the `AWS_PROFILE` environment variable to the name of the profile, (dev or prod, in this case), 
you can point credsmash at the appropriate account.

See https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs for more information.

## Usage
```
Usage: credsmash [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config PATH
  -t, --table-name TEXT     DynamoDB table to use for credential storage
  -k, --key-id TEXT         the KMS key-id of the master key to use. See the
                            README for more information. Defaults to
                            alias/credsmash
  --context <TEXT TEXT>...  the KMS encryption context to use.Only works if
                            --key-id is passed.
  --help                    Show this message and exit.

Commands:
  delete            Delete every version of a single secret
  delete-many       Delete every version of all matching secrets
  find-many         Find all secrets matching <pattern>
  find-one          Find exactly one secret matching <pattern>
  get               Fetch the latest, or a specific version of a...
  get-all           Fetch the latest version of all secrets
  list              List all secrets & their versions.
  prune             Delete all but the latest version of a single...
  prune-many        Delete all but the latest version of all...
  put               Store a secret
  put-many          Store many secrets
  render-template   Render a configuration template....
  render-templates  Render multiple configuration templates -...
  setup-dynamodb    Setup the credential table in AWS DynamoDB
```

## IAM Policies

### Secret Writer
You can put or write secrets to credsmash by either using KMS Key Grants, KMS Key Policies,
or IAM Policies. If you are using IAM Policies, the following IAM permissions are the minimum 
required to be able to put or write secrets:

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
If you are using Key Policies or Grants, then the `kms:GenerateDataKey` is not required in the policy for the 
IAM user/group/role. Replace `AWSACCOUNTID` with the account ID for your table, and replace the KEY-GUID with the 
identifier for your KMS key (which you can find in the KMS console).

### Secret Reader
You can read secrets from credsmash with the get or getall actions by either using KMS Key Grants, KMS Key 
Policies, or IAM Policies. If you are using IAM Policies, the following IAM permissions are the minimum 
required to be able to get or read secrets:
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
If you are using Key Policies or Grants, then the `kms:Decrypt` is not required in the policy for
the IAM user/group/role. Replace `AWSACCOUNTID` with the account ID for your table, and replace 
the KEY-GUID with the identifier for your KMS key (which you can find in the KMS console). Note 
that the `dynamodb:Scan` permission is not required if you do not use wildcards in your `get`s.

## Security Notes
Any IAM principal who can get items from the credential store DDB table, and can call KMS.Decrypt,
can read stored credentials.

The target deployment-story for `credsmash` is an EC2 instance running with an IAM role that has 
permissions to read the credential store and use the master key. Since IAM role credentials are 
vended by the instance metadata service, by default, any user on the system can fetch creds and 
use them to retrieve credentials. That means that by default, the instance boundary is the security
boundary for this system. If you are worried about unauthorized users on your instance, you should 
take steps to secure access to the Instance Metadata Service (for example, use iptables to block 
connections to 169.254.169.254 except for privileged users). Also, because credsmash is written in 
python, if an attacker can dump the memory of the credsmash process, they may be able to recover 
credentials. This is a known issue, but again, in the target deployment case, the security boundary 
is assumed to be the instance boundary.

## Frequently Asked Questions (FAQ)

### 1. Where is the master key stored?
The master key is stored in AWS Key Management Service (KMS), where it is stored in secure 
HSM-backed storage. The Master Key never leaves the KMS service.

### 2. How is credential rotation handled?
Every credential in the store has a version number. Whenever you want to a credential to a new 
value, you have to do a `put` with a new credential version. For example, if you have `foo` 
version 1 in the database, then to update `foo`, you can put version 2. You can either specify 
the version manually (i.e. `echo 'bar' | credsmash put foo - -v 2`), or you can omit the `-v` flag, 
which  will attempt to autoincrement the version number (for example, `echo 'baz' | credsmash put foo -`). 
Whenever you do a `get` operation, credsmash will fetch the most recent (highest version) version of that 
credential. So, to do credential rotation, simply put a new version of the credential, and clients fetching 
the credential will get the new version.

### 3. How much do the AWS services needed to run credsmash cost?
tl;dr: If you are using less than 25 reads/sec and 25 writes per second on DDB today, 
it will cost ~$1/month to use credsmash.

The master key in KMS costs $1 per month.

The credential store DDB table uses 1 provisioned read and 1 provisioned write throughput, along 
with a small amount of actual storage. This falls well below the free tier for DDB (25 reads and 
25 writes per second). If you are already a heavy DDB user and exceed the free tier, the credential 
store table will cost about $0.53 per month (mostly from the write throughput).

If you are using credsmash heavily and need to increase the provisioned reads/writes, you may incur 
additional charges. You can estimate your bill using the AWS Simple Monthly Calculator 
(http://calculator.s3.amazonaws.com/index.html#s=DYNAMODB).

### 4. Why DynamoDB for the credential store? Why not S3?
DDB fits the application really well. Having very low latency fetches are really nice if credsmash is 
in the critical path of spinning up an application. Being able to turn throughput up or down based on
load and requirements are also great things to have in a config management tool. Also, as credsmash gets 
into more complex credential management functions, the query capabilities of DDB get super handy.

That said, S3 support may happen someday.

### 5. Where can I learn more about use cases and context for something like credsmash?
Check out this blog post: http://blog.fugue.it/2015-04-21-aws-kms-secrets.html
