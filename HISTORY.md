
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
   key_id = dev-credkey
   [credsmash:encryption_context]
   environment=production
   purpose=web
   ```

   You can override this by providing the `--table-name` and `--key-id` parameters to each command.
    
   If you provide `--context` to a command, it will only append each key-value pair to the context,
   rather than overwriting it completely.

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
      
