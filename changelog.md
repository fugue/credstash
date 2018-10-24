# Changelog

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
