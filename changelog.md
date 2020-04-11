# Changelog

## 1.17.1
* Bugfix: #291 Move `kms_region` optional parameter to end of parameter list to preserve existing functionality when parameters are used positionally

## 1.17.0
* New: add `--kms-region` argument to set the KMS region independently from the DDB region. This allows the use of DDB tables in multiple regions with the same KMS key, for example, with DDB Global Tables
* New: `get_session()` now supports passing in only the `profile_name` without AKIDs or SAKs (@eisjcormier)
* Bugfix: #273 #274 Disable logging when `credstash` is imported as a library. This allows `credstash` to be used in contexts where writing to the local disk is not allowed, such as AWS Lambda
* Bugfix: #269 Remove incompatible Python 3 code to ensure compatibility with Python 2
* Bugfix: #276 Do not catch errors when `credstash` is imported as a library

## 1.16.2
* New: Smarter cached session handling was added, with support for multiple sessions keyed by AKID
* New: Configurable logging was added
* New: @VincentHokie added the ability to pass a custom session to `getAllSecrets` and `listSecrets` 
* Bugfix: An empty dict is returned from getall when there are no secrets, rather than an error
* Bugfix: @aerostitch fixed Python 3.8 syntax warnings
* New languages: Links to Erlang and Rust implementations of `credstash` have been added

## 1.16.1
* Bugfix: @corrjo fixed a bug in the tagging feature 
* Bugfix: @jamebus fixed a bug in `putall`

## 1.16.0
* New: @freddyVandalay added a programmatic way to autoversion: `putSecretAutoversion`
* New: @corrjo added the ability to tag the `credstash` DDB table using `credstash setup --tags Tag=Value`
* New: @alkersan added the ability to specify the `credstash` DDB table using an environment variable
* New: @cheethoe added the ability to pass custom dynamodb/kms sessions to `putSecret`
* Bugfix: @dbanttari fixed large deletes and made them more efficient by using `query` instead of `scan`
* Bugfix: Update to pyyaml>=4.2b1 due to security vulnerability in older versions
* Added basic integration tests

## 1.15.0
* New: Arthur Burkart added credential comments
* Updated: added tox, and improved packaging
* New: @jimbocoder added a threadpool to `getall` to fetch groups of credentials faster
* New: @a12k added a migration script if you are using old hashing methods
* Bugfix: @jomunoz and @jessemyers removed unsupported hashing methods and bumped the `cryptography` dependency

## 1.14.0

* New: @stephen-164 added -f to `credstash get` for wildcard gets
* New: @mrwacky42 added `credstash keys`
* New: @evanstachowiak added `credstash putall`
* Updated: @gene1wood, @nkhoshini, and @wyattwalter updated the docs
* Bugfix: @pm990320 fixed a bug by adding pagination for large credential stores
* Bugfix: @artburkart fixed a bug where writing csv files did not have proper line separators
* Removed: Python 3.2 removed from build matrix

## 1.13.4
* Set upper bound of `cryptography` to 2.1

## 1.13.3
* Only fetch the session resource and client once
* README updates for c# and node imlpementations
* python 3.2 removed from build matrix
* fixed hmac checking
* removed build constraint on `cryptography` <2.0
