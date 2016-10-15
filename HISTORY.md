
# Changes between `credstash` and `credsmash`

 - We let `boto3` handle it's own configuration, so we removed these options: `--region`, `--profile` or `--arn`. There are two main ways you can configure `boto3` now;
     - Method 1: Create a file at `~/.aws/credentials`, and choose the desired profile by setting environment `AWS_PROFILE=myprofile`
     - Method 2: Create a custom `aws.cfg` and point to it with the environment variable `AWS_CONFIG_FILE=/path/to/my/aws.cfg`

   [More info on configuration in the boto3 docs](http://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration)
   
   Example `aws.cfg` -

   ```cfg
   [default]
   aws_access_key_id = xxxxx
   aws_secret_access_key = yyyyy
   region = us-east-1
   ```

 - You can load options for `credsmash` from a configuration file. Use, `--config`, or by setting the 
   `CREDSMASH_CONFIG` environment variable. (default- `/etc/credsmash.cfg`)
   
   Example `credsmash.cfg` -
   
   ```cfg
   [credsmash]
   table_name = dev-credential-store
   [credsmash:key_service:kms]
   key_id = dev-credkey
   encryption_context =
     environment = production
     purpose = web
   ```

   You can override this by providing the `--table-name` and `--key-id` parameters to each command.
    
   Providing `--context` via the CLI will only work if manually specifying the `--key-id`, otherwise
   it will read from the configuration file.

 - The signatures of nearly every command has changed,
 
   - `credsmash get <name> <file>` 
      - No longer supports patterns, use `credsmash find-one` or `credsmash find-many`
      - Extra argument `<file>`, which is stdout by default
      - Output is `raw` by default, and doesn't include any newlines
   - `credsmash get-all <file>`
      - Changed from `getall` to `get-all`
      - Output is `json` by default (other options are `csv` and `yaml`)
   - `credsmash put <name> <file>`
      - the old `-a` or `--autoversion` option is implicit; override by providing `--version`
      - expects to read credential from `<file>`, so to write a value in one command is a little verbose-
        `echo "myvalue" | credsmash put secretname -`
      - Default input format is `raw` but supports `json`, `csv` and `yaml`; 
   - `credsmash put-many <file>`
      - Similar to `put` except it supports multiple values, from formatted `json`, `csv` and `yaml`.
   - `credsmash list <pattern>`
      - Now supports a `pattern` parameter which uses [`fnmatch`](https://docs.python.org/2/library/fnmatch.html)
   - `credsmash delete <name>`
      - Only deletes an exactly-matching secret
   - `credsmash delete-many <pattern>`
      - Deletes any secret matching the pattern (again using `fnmatch`)
   - `credsmash prune <name>`
      - New command, that removes any old versions of `name`
   - `credsmash prune-many <pattern>`
      - New command, removes any old versions matching the pattern (again using `fnmatch`)
   - `credsmash find-one <pattern> <file>`
      - New command, replaces old wild-card functionality in `credsmash get`
      - Fails if there isn't exactly one result
   - `credsmash find-many <pattern> <file>`
      - Works the same as `find-one` except returns all results (and doesn't support `raw`)
      
 - By default, new secrets are stored as `Binary` types in DynamoDB; these can't be read by existing `credstash`
   clients. Please set, `algorithm = aes-ctr-legacy` in your `credsmash.cfg` if you need to support `credstash` clients.
   
   Note: If you store a binary file, you can only retrieve it using the `raw` format, for example -
   `credsmash get <name> <file> -f raw`

 - We support AES-CTR or AES-GCM mode, you can configure like so-
 
   AES-CTR with SHA512:
   ```cfg
   [credsmash]
   table_name = dev-credential-store
   key_id = dev-credkey
   algorithm = aes-ctr
   [credsmash:aes-ctr]
   key_length=64
   digest_method=SHA512
   ```

   AES-GCM with 32-byte key:

   ```cfg
   [credsmash]
   table_name = dev-credential-store
   key_id = dev-credkey
   algorithm = aes-gcm
   [credsmash:aes-gcm]
   key_length=32
   ```
 - We support writing shell & json script templates, directly from `credsmash` data.
   
   eg, `credsmash render-templates manifest.yaml --manifest-format yaml`

   ```yaml
    - source: /path/to/my/template.j2
       destination: /path/to/output/myfile
      mode: 0600
      owner: root
      group: root
    - source: /path/to/another/template.j2
      destination: /path/to/output/anotherfile
      mode: 0600
      owner: root
      group: root
    ```

 - You can define alternative key-services, by using the `credsmash.key_service` [entry point](http://setuptools.readthedocs.io/en/latest/pkg_resources.html#entry-points).
 
  eg, to load a key service called `custom_ks`
  
   ```cfg
   [credsmash]
   key_service = custom_ks
   [credsmash:key_service:custom_ks]
   option_1 = a
   option_2 = b
   ```

 - You can define alternative storage-services, by using the `credsmash.storage_service` [entry point](http://setuptools.readthedocs.io/en/latest/pkg_resources.html#entry-points).
 
  eg, to load a storage service called `custom_s3_backend`
  
   ```cfg
   [credsmash]
   storage_service = custom_s3_backend
   [credsmash:storage_service:custom_s3_backend]
   option_1 = a
   option_2 = b
   ```

 - By default `credsmash put` will check if the value of a secret has changed. Use `--version` or `--no-compare` to
   avoid this comparison.

 - `credsmash` has a straight-forward API for pythonic access.
 
   ```py
   import credsmash
   # Auto-configure a session from your 
   # /etc/credsmash.cfg or CREDSMASH_CONFIG environment variable
   session = credsmash.get_session()
   # or, provide options directly-
   session = credsmash.get_session(table_name='my-dynamodb-table', key_id='my-key')

   # Access a secret
   plaintext = session.get_one('my_secret')
   # search for secrets
   secret_name, plaintext = session.find_one('s3_prod_*')
   secrets = session.find_many('s3_*')
   ```
