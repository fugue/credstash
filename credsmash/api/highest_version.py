from __future__ import absolute_import, division, print_function, unicode_literals

from boto3.dynamodb.conditions import Key as ConditionKey


def get_highest_version(secrets_table, secret_name):
    response = secrets_table.query(
        Limit=1,
        ScanIndexForward=False,
        ConsistentRead=True,
        KeyConditionExpression=ConditionKey("name").eq(secret_name),
        ProjectionExpression="version"
    )

    if response["Count"] == 0:
        return 0
    try:
        return int(response["Items"][0]["version"], 10)
    except ValueError:
        raise RuntimeError('Could not parse current version: %s' % response["Items"][0]["version"])
