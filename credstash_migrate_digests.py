#!/usr/bin/env python
# Updates digests in a credstash dynamodb table. Default behavior is to 
# update all deprecated WHIRLPOOL and RIPEMD digests to the default SHA256.
# Clears the way for credstash update removing deprecated hashes.
# 
# Usage: AWS_PROFILE=my_profile python3 credstash_migrate_digests.py

import sys
from subprocess import Popen, PIPE
from collections import defaultdict
from boto3 import resource
import credstash


def main():
    UPDATED_DIGEST = 'SHA512'
    DIGESTS_TO_UPDATE = ['WHIRLPOOL', 'RIPEMD']

    keys = defaultdict(lambda:0)
    keys_to_update = []

    dynamodb_resource = resource('dynamodb')
    table = dynamodb_resource.Table('credential-store')
    response = table.scan()

    items = response['Items']

    # appending all dynamodb entries to items dict
    while True:
        if response.get('LastEvaluatedKey'):
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items += response['Items']
        else:
            break

    # storing latest version of keys with their digests
    for i in range(len(items)):
        try:
            digest = items[i]['digest']
            version = int(items[i]['version'])
            key = items[i]['name']
        except:
            continue

        if key in keys:
            if version > keys[key][0]:
                keys[key][0] = version
                keys[key][1] = digest
        else:
            keys[key] = [version, digest]

    # store keys to be updated
    for k, v in keys.items():
        if v[1] in DIGESTS_TO_UPDATE:
            keys_to_update.append(k)

    # confirms update of digests
    if len(keys_to_update):
        print('\nThe following keys will be updated to {0}:\n'.format(UPDATED_DIGEST))
        for key in keys_to_update:
            print('{0}\n'.format(key))
        confirmed = None
        while not confirmed:
            val = input('Continue? y/n ')
            if val.lower() == 'y' or val.lower() == 'yes':
                confirmed = True
            elif val.lower() == 'n' or val.lower() == 'no':
                print('\nexiting...\n')
                sys.exit()
            else:
                print('\nInvalid input\n')
    else:
        print('\nNo digests to update!\n')
        sys.exit()

    # updating deprecated digests
    for key in keys_to_update:
        p = Popen(['credstash', 'get', key], stdout=PIPE, stderr=PIPE)
        secret, err = p.communicate()
        secret = secret[:-1] # removes credstash-added newline for stdout
        if not err:
            p = Popen(['credstash', 'put', key, secret, '-a', '-d', UPDATED_DIGEST], stdout=PIPE)
            update, err = p.communicate()
            print('{0} has been updated!\n'.format(key))
        else:
            print('Error found, skipping update of {0}. Error: {1}'.format(key, err))

if __name__ == '__main__':
    main()
