#!/usr/bin/env bats

# test basic CRUD with separate KMS and DDB regions
# these tests require a duplicated DDB table in us-east-2
@test "put secret into credstash" {
    credstash --region us-east-2 --kms-region us-east-1 put __batstestcred1 secretvalue
}

@test "read secret from credstash" {
    SECRET=$(credstash --region us-east-2 --kms-region us-east-1 get __batstestcred1)
    [ "$SECRET" = secretvalue ]
}

@test "add a new version to a secret in credstash" {
    credstash --region us-east-2 --kms-region us-east-1 put __batstestcred1 secretvalue2 -a
}

@test "read latest version of a secret from credstash" {
    SECRET=$(credstash --region us-east-2 --kms-region us-east-1 get __batstestcred1)
    [ "$SECRET" = secretvalue2 ]
}

@test "read previous version of a secret from credstash" {
    SECRET=$(credstash --region us-east-2 --kms-region us-east-1 get __batstestcred1 -v 1)
    [ "$SECRET" = secretvalue ]
}

@test "delete a secret from credstash" {
    credstash --region us-east-2 --kms-region us-east-1 delete __batstestcred1
}