# loads dynamoDB data from file that has been created with the following command: aws dynamodb scan --table-name SIEM > ./DbBackup/SIEM.json

import json
import boto3
from boto3.dynamodb.conditions import Key, Attr


SOURCE = './DbBackup/MonitorLizardDynamoDB.json'
DEST_TABLE = 'SIEM-Backup'



client = boto3.client('dynamodb')

with open(SOURCE) as json_file:
    data = json.load(json_file)
    for item in data['Items']:
    	#aws dynamodb put-item --table-name SIEM-Backup --item file://SIEM-test.json

    	response = client.put_item(
    		TableName = DEST_TABLE,
    		Item = item)

        