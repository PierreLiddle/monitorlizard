# Monitor Lizard
Threat detector engine for AWS events stored in Elasticsearch

Setup:
1. Setup [Security Data Lake](https://github.com/awsvolks/securitydatalake)
2. Lambda for each use case incl environment variables
3. DynamoDB
4. SNS topic


## Lambda Environment Variables for each use case Lambda:

Key | Value
--- | ---
**DynamoDB** | SIEM
**ES_AUTH_TYPE** | esl
**ES_ENDPOINT** | my-elk-cluster-7fy3xguvkfnhczlw3yxqui.us-east-2.es.amazonaws.com
**ES_LOG_LEVEL** | DEBUG
**ES_LOGIN_ONLY_FOR_ESL_AUTHTYPE** | billybob
**ES_PWD_ONLY_FOR_ESL_AUTHTYPE** | Pwd_for_esl_auth_type
**ES_REGION** | us-east-2
**SNS_TOPIC_ARN** | arn:aws:sns:us-east-2:792837498234792:SOC-ALERT-TOPIC


## DynamoDB Setup
Partition key: RuleId (String)
Sort key: RuleType (String)

Demo Document:

```javascript
{
  "AlertPeriodMinutes": 3600,
  "AlertText": "New or infrequent use of IAM access keys in production account 87654321:\nThe following IAM access keys where used for S3 create events for the first time within the alert window. ",
  "Description": "Search for all accessKeys who performed S3 create events in the last n minutes (IntervallMinutes). Alert if accessKey hasn't been used for this operation within the last n hours (AlertPeriodMinutes). Search in index for 'userIdentity.accessKeyId', eventSource=s3.amazonaws.com, eventName=Create*",
  "ES_Index": "cloudtrail*",
  "LastAggResult": {
    "AKIA4RKH6JM6CBCA3X5U": 1595122200,
    "ASIA4RKH6JM6KFARZXXX": 1595122200
  },
  "LastRun": 1505857721,
  "Query": "{\n    \"query\": {\n    \"bool\": {\n      \"must\": [\n        {\n          \"wildcard\": {\n            \"eventName.keyword\": \"Create*\"\n          }\n        }\n      ],\n      \n      \"filter\": [\n        {\"term\": {\"eventSource.keyword\":\"s3.amazonaws.com\"}},\n        {\"term\": {\"recipientAccountId.keyword\":\"121828696892\"}},\n        { \"range\": { \"eventTime\": { \"gte\": \"2020-07-25T08:00:00.000Z\" }}}\n      ] \n    }\n  },\n  \"size\":0,\n  \"aggs\": {\n    \"my_count\": {\n      \"terms\": {\n        \"field\": \"userIdentity.accessKeyId.keyword\"\n          }\n        }\n    }\n}",
  "RuleId": "Test",
  "RuleType": "User activity anomaly",
  "RunScheduleInMinutes": 60
}
```


```python
for Rule in response["Items"]:
        
        if Rule["LastRun"]+(Rule["RunScheduleInMinutes"]*60) < int(time.time()):
        
            print("--------------------------")
            print( "Executing rule: "+Rule["RuleId"] )
 
            runRule(esClient, dynamodb_table, sns, Rule["RuleId"], Rule["RuleType"])
            
            # Updateing SIEM rule last run time stamp
            response = dynamodb_table.update_item(
                Key={
                    'RuleId': Rule["RuleId"],
                    'RuleType': Rule["RuleType"]
                },
                UpdateExpression="set LastRun=:l",
                ExpressionAttributeValues={
                    ':l': int(time.time())
                },
                ReturnValues="UPDATED_NEW"
            )
        else:
            print("--------------------------")
            print( "Skipping SIEM rule: "+Rule["RuleId"] )
```
