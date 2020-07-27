# Monitor Lizzrd
SIEM light for AWS events stored in Elasticsearch

Setup:
1. Setup [Security Data Lake](https://github.com/awsvolks/securitydatalake)
2. Lambda for each use case incl environment variables
3. DynamoDB
4. SNS topic





## Lambda Environment Variables:
Key | Value
--- | ---
DynamoDB | SIEM
ES_AUTH_TYPE | esl
ES_ENDPOINT | my-elk-cluster-7fy3xguvkfnhczlw3yxqui.us-east-2.es.amazonaws.com
ES_LOG_LEVEL | DEBUG
ES_LOGIN_ONLY_FOR_ESL_AUTHTYPE | billybob
ES_PWD_ONLY_FOR_ESL_AUTHTYPE | Pwd_for_esl_auth_type
ES_REGION | us-east-2
SNS_TOPIC_ARN | arn:aws:sns:us-east-2:792837498234792:SOC-ALERT-TOPIC


## DynamoDB Setup
Partition key: RuleId (String)
Sort key: RuleType (String)

Demo Document:
```javascript
{
  "AlertPeriodMinutes": 3600,
  "AlertText": "New or infrequent use of access keys. The following IAM access keys where used for S3 create events for the first time within the alert period. ",
  "Description": "Search for all accessKeys who performed S3 create events in the last n minutes (IntervallMinutes). Alert if accessKey hasn't been used for this operation within the last n hours (AlertPeriodMinutes)",
  "Index": "cloudtrail*",
  "IntervallMinutes": 60,
  "LastAggResult": "{\n    \"AKIA4RKH6JM6CBCA3X5U\" : 1595122200,\n    \"ASIA4RKH6JM6KFARZXXX\" : 1595122200 \n}",
  "Query": "{\n    \"query\": {\n    \"bool\": {\n\n      \"must_not\": [\n        {\n          \"match\": {\n            \"userIdentity.type\": \"AWSService\"\n          }\n        }\n      ],\n      \n      \"must\": [\n        {\n          \"wildcard\": {\n            \"eventName.keyword\": \"Create*\"\n          }\n        }\n      ],\n      \n      \"filter\": [\n        {\"term\": {\"eventSource.keyword\":\"s3.amazonaws.com\"}},\n        { \"range\": { \"eventTime\": { \"gte\": \"2020-07-25T08:00:00.000Z\" }}}\n      ] \n    }\n  },\n  \"size\":0,\n  \n  \"aggregations\": {\n    \"my_count\": {\n      \"terms\": {\n        \"field\": \"userIdentity.accessKeyId.keyword\",\n        \"order\": { \"_count\": \"desc\" },\n        \"size\":5\n          }\n        }\n    }\n}",
  "RuleId": "Test",
  "RuleType": "User activity anomaly"
}
```
