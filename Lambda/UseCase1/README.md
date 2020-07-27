# Monitor Lizard Use Case “User activity anomaly”

## Introduction

Find activities that haven’t been performed by a particular user, IP or accessKey in the last n minutes or for the first time.

Example 1:
Find EC2 create events performed from a “new” IAM access key. 
Autoscale user creates EC2 instances all the time. A malicious user does it for the first time.
Example 2: 
New IAM users performed S3 create events the first time in n minutes 
Example 3:
User performing DynamoDB activities within production account



## Alert Example

New or infrequent use of IAM access keys in production account 87654321:
The following IAM access keys where used for S3 create events for the first time within the alert window. 
Alert Value: ASIA4RKH6JM6KFARZFU5
Rule Id: Test
Rule Type: User activity anomaly
Elasticsearch Index: cloudtrail*
Alert window: 3600 minutes


## Example #1 

Find new accessKeys that performed S3 create events

Query (executed in Kibana Dev-Tools )

NOTE: 

* always use “.keyword” in must or must_not sections
* filter-range-eventTime will be replaced (or added) by the current time minus the alert window range at each execution


```
GET cloudtrail*/_search
{
    "query": {
    "bool": {
      "must": [
        {
          "wildcard": {
            "eventName.keyword": "Create*"
          }
        }
      ],
      "filter": [
        {"term": {"eventSource.keyword":"s3.amazonaws.com"}},
        {"term": {"recipientAccountId.keyword":"861828696892"}},
        { "range": { "eventTime": { "gte": "2020-07-25T08:00:00.000Z" }}}
      ] 
    }
  },
  "size":0,
  "aggs": {
    "my_count": {
      "terms": {
        "field": "userIdentity.arn.keyword"
          }
        }
    }
}
```

Result found two IAM users that performed S3 create events since the given eventTime

```
...
"aggregations" : {
    "my_count" : {
    "doc_count_error_upper_bound" : 0,
    "sum_other_doc_count" : 0,
    "buckets" : [
        {
          "key" : "arn:aws:iam::861828696892:user/awsvolker",
          "doc_count" : 4
        },
        {
          "key" : "arn:aws:sts::861828696892:assumed-role/God/awsvolks-Isengard",
          "doc_count" : 1
        }
      ]
...
```

Example DynamoDB Test Rule

```
{
  "RuleId": "Test",
  "RuleType": "User activity anomaly",
  "RunScheduleInMinutes": 60,
  "AlertPeriodMinutes": 3600,
  "AlertText": "New or infrequent use of IAM access keys in production account 87654321:\nThe following IAM access keys where used for S3 create events for the first time within the alert window. ",
  "Description": "Search for all accessKeys who performed S3 create events in the last n minutes (IntervallMinutes). Alert if accessKey hasn't been used for this operation within the last n hours (AlertPeriodMinutes). Search in index for 'userIdentity.accessKeyId', eventSource=s3.amazonaws.com, eventName=Create*",
  "LastAggResult": {
    "AKIA4RKH6JM6CBCA3X5U": 1595122200,
    "ASIA4RKH6JM6KFARZXXX": 1595122200
  },
  "Query": "{\n    \"query\": {\n    \"bool\": {\n\n      \"must_not\": [\n        {\n          \"match\": {\n            \"userIdentity.type\": \"AWSService\"\n          }\n        }\n      ],\n      \n      \"must\": [\n        {\n          \"wildcard\": {\n            \"eventName.keyword\": \"Create*\"\n          }\n        }\n      ],\n      \n      \"filter\": [\n        {\"term\": {\"eventSource.keyword\":\"s3.amazonaws.com\"}},\n        {\"term\": {\"recipientAccountId.keyword\":\"861828696892\"}},\n        \n        { \"range\": { \"eventTime\": { \"gte\": \"2020-05-01T00:00:00.000Z\" }}}\n      ] \n    }\n  },\n  \"size\":0,\n  \n  \"aggs\": {\n    \"my_count\": {\n      \"terms\": {\n        \"field\": \"userIdentity.accessKeyId.keyword\",\n        \"order\": { \"_count\": \"desc\" },\n        \"size\":5\n          }\n        }\n    }\n}",
  "ES_Index": "cloudtrail*"
}
```



## Example #2:

Find new IAM access keys, that performed any DynamoDB activity (except keys starting with ASIA*)

Query (executed in Kibana Dev-Tools )

NOTE: 

* always use “.keyword” in must or must_not sections
* filter-range-eventTime will be replaced (or added) by the current time minus the alert window range at each execution

```
GET cloudtrail-2020-07-21/_search
{
    "query": {
    "bool": {
      "must_not": [{"wildcard":{"userIdentity.accessKeyId.keyword":"ASIA*"}}],
      "filter": [
        {"term": {"eventSource.keyword":"dynamodb.amazonaws.com"}},
        {"term": {"recipientAccountId.keyword":"051687089423"}},
        { "range": { "eventTime": { "gte": "2020-07-20T08:00:00.000Z" }}}
      ] 
    }
  },
  "size":0,
  "aggs": {
    "my_count": {
      "terms": {
        "field": "userIdentity.accessKeyId.keyword"
          }
        }
    }
}
```



