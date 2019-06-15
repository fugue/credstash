# Changelog

## 1.16.0 (forthcoming)
* New: @freddyVandalay added a programmatic way to autoversion: `putSecretAutoversion`
* New: @corrjo added the ability to tag the `credstash` DDB table using `credstash setup --tags Tag=Value`
* New: @alkersan added the ability to specify the `credstash` DDB table using an environment variable
* New: @cheethoe added the ability to pass custom dynamodb/kms sessions to `putSecret`
* Bugfix: @dbanttari fixed large deletes and made them more efficient by using `query` instead of `scan`
* Bugfix: Update to pyyaml>=4.2b1 due to security vulnerability in older versions

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
