# Changelog

## 1.14.0

* New: @stephen-164 added -f to `credstash get` for wildcard gets
* New: @mrwacky42 added `credstash keys`
* New: @evanstachowiak added `credstash putall`
* Updated: @gene1wood, @nkhoshini, and @wyattwalter updated the docs
* Bugfix: @pm990320 fixed a bug by adding pagination for large credential stores
* Bugfix: @artburkart fixed a bug where writing csv files did not have proper line separators

## 1.13.4
* Set upper bound of `cryptography` to 2.1

## 1.13.3
* Only fetch the session resource and client once
* README updates for c# and node imlpementations
* python 3.2 removed frmo build matrix
* fixed hmac checking
* removed build constraint on `cryptography` <2.0
