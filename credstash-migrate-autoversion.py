import boto3
import credstash
import copy


def updateVersions(region="us-east-1", table="credential-store"):
    '''
    do a full-table scan of the credential-store,
    and update the version format of every credential if it is an integer
    '''
    dynamodb = boto3.resource('dynamodb', region_name=region)
    secrets = dynamodb.Table(table)

    response = secrets.scan(ProjectionExpression="#N, version, #K, contents, hmac",
                            ExpressionAttributeNames={"#N": "name", "#K": "key"})

    items = response["Items"]

    for old_item in items:
        try:
            int(old_item['version'])
            new_item = copy.copy(old_item)
            new_item['version'] = credstash.paddedInt(new_item['version'])
            if new_item['version'] != old_item['version']:
                secrets.put_item(Item=new_item)
                secrets.delete_item(Key={'name': old_item['name'], 'version': old_item['version']})
        except:
            print "Skipping item: %s, %s" % (old_item['name'], old_item['version'])


if __name__ == "__main__":
    updateVersions()
