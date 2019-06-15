#!/usr/bin/env bats

# test basic CRUD
@test "put secret into credstash" {
    credstash put __batstestcred1 secretvalue
}

@test "read secret from credstash" {
    SECRET=$(credstash get __batstestcred1)
    [ "$SECRET" = secretvalue ]
}

@test "add a new version to a secret in credstash" {
    credstash put __batstestcred1 secretvalue2 -a
}

@test "read latest version of a secret from credstash" {
    SECRET=$(credstash get __batstestcred1)
    [ "$SECRET" = secretvalue2 ]
}

@test "read previous version of a secret from credstash" {
    SECRET=$(credstash get __batstestcred1 -v 1)
    [ "$SECRET" = secretvalue ]
}

@test "delete a secret from credstash" {
    credstash delete __batstestcred1
}