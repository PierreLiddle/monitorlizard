#Use Case “User activity anomaly”

## Introduction

Find activities that haven’t been performed by a particular user, IP or accessKey in the last n minutes or for the first time {at least n times}

**Example 1:**
Find EC2 create events performed from a “new” IAM user. 
Autoscale user creates EC2 instances all the time. A malicious user does it for the first time.

**Example 2:** 
New IAM users performed S3 create bucket event for the first time in n minutes 

**Example 3:**
New user performing DynamoDB activities within production account

**Example 4:**
More than 3 user signin failures within 5 minutes



## Rule query logic
The query of each rule is defined in the Lucene query language that used in the Kibana Dev-Tools **excluding** the first line `GET cloudtrail*/_search` 

The following example query searches for all users that performed EC2 _AuthorizeSecurityGroupIngress_ events in a particular account. For test purposes, the date range filter term is still part of this query but is changed (or added) dynamically during every rule execution to greater than {NOW - AlertPeriodMinutes}.

The query should be performed manually in Kibana-Dev tools for test purposes to test the query logic.  

```
GET cloudtrail*/_search     <<< remove when defining rule query in DynamoDB !!!
{
    "query": {
    "bool": {
      "filter": [
        {"term": {"eventName.keyword":"AuthorizeSecurityGroupIngress"}},
        {"term": {"eventSource.keyword":"ec2.amazonaws.com"}},
        {"term": {"recipientAccountId.keyword":"861828696892"}},
        
        { "range": { "eventTime": { "gte": "2020-07-25T08:00:00.000Z" }}}
      ] 
    }
  },
  "size":0,
  
  "aggs": {
    "my_count": {
      "terms": {
        "field": "userIdentity.sessionContext.sessionIssuer.arn.keyword"
          }
        }
    }
}
```

## Rule alert logic

New users launching EC2 instance (AlertPeriodInMinutes=3600, AlertMinimumEventCount=1)
> Alert by user on every EC2 launch event if the user hasn't performed this event in the last 60 hours 

New users creating S3 bucket (AlertPeriodInMinutes=3600, AlertMinimumEventCount=1)
> Alert by user on every create bucket event if the user hasn't performed this event in the last 60 hours 

Failed user authentication (AlertPeriodInMinutes=5, AlertMinimumEventCount=3)
> Alert by user if the query found more than 3 failed user logins within the last 5 minutes

  
            

## Alert Example

New or infrequent use of IAM access keys in production account 87654321:
The following IAM access keys where used for S3 create events for the first time within the alert window. 
Alert Value: ASIA4RKH6JM6KFARZFU5
Rule Id: Test
Rule Type: User activity anomaly
Elasticsearch Index: cloudtrail*
Alert window: 3600 minutes


## Example #1 

Find new IAM users that performed EC2 RunInstances event in the main account (started instance)

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
            "eventName.keyword": "RunInstances"
          }
        }
      ],
      
      "filter": [
        {"term": {"eventSource.keyword":"ec2.amazonaws.com"}},
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

Result found two IAM users that performed EC2 launch events since the given eventTime

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
  "RuleId": "New users launching EC2 instance",
  "RuleType": "User activity anomaly",
  "RunScheduleInMinutes": 60,
  "AlertPeriodMinutes": 3600,
  "AlertMinimumEventCount": 1,
  "AlertText": "New or infrequent launch EC2 instance event by user in production account:\nThe following IAM users where used for EC2 launch events for the first time within the alert window. ",
  "Description": "Search for all userIdentity.arn who performed EC2 create events in the last n minutes (IntervallMinutes). Alert if accessKey hasn't been used for this operation within the last n hours (AlertPeriodMinutes).",
  "LastAggResult": {
    "AKIA4RKH6JM6CBCA3X5U": 1595122200,
    "ASIA4RKH6JM6KFARZXXX": 1595122200
  },
  "LastRun": 1595858028,
  "Query": "{\n    \"query\": {\n    \"bool\": {\n\n      \"must_not\": [\n        {\n          \"match\": {\n            \"userIdentity.type\": \"AWSService\"\n          }\n        }\n      ],\n      \n      \"must\": [\n        {\n          \"wildcard\": {\n            \"eventName.keyword\": \"RunInstances*\"\n          }\n        }\n      ],\n      \n      \"filter\": [\n        {\"term\": {\"eventSource.keyword\":\"ec2.amazonaws.com\"}},\n        {\"term\": {\"recipientAccountId.keyword\":\"861828696892\"}},\n        \n        { \"range\": { \"eventTime\": { \"gte\": \"2020-05-01T00:00:00.000Z\" }}}\n      ] \n    }\n  },\n  \"size\":0,\n  \n  \"aggs\": {\n    \"my_count\": {\n      \"terms\": {\n        \"field\": \"userIdentity.accessKeyId.keyword\",\n        \"order\": { \"_count\": \"desc\" },\n        \"size\":5\n          }\n        }\n    }\n}",
  "ES_Index": "cloudtrail*"
}
```



## Example #2:

Find IAM users that created a new S3 bucket in the main account
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
            "eventName.keyword": "CreateBucket"
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

### Example DynamoDB Test Rule
```
{
  "AlertPeriodMinutes": 3600,
  "AlertMinimumEventCount": 1,
  "AlertText": "New user created bucket in production account 12345678:\nThe following IAM access keys where used for S3 create bucket events for the first time within the alert window. ",
  "Description": "Search for users that performed S3 create bucket events recently. Alert if accessKey hasn't been used for this operation within the last n hours (AlertPeriodMinutes). Search in index for 'userIdentity.accessKeyId', eventSource=s3.amazonaws.com, eventName=Create*",
  "ES_Index": "cloudtrail*",
  "LastAggResult": {
    "AKIA4RKH6JM6CBCA3X5U": 1595122200,
    "ASIA4RKH6JM6KFARZXXX": 1595122200
  },
  "LastRun": 1595858028,
  "Query": "{
    "query": {
    "bool": {
      "must": [
        {
          "wildcard": {
            "eventName.keyword": "CreateBucket"
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
}",
  "RuleId": "New user created S3 bucket",
  "RuleType": "User activity anomaly",
  "RunScheduleInMinutes": 60
}
```


## Example #4

User creates more then n failed signin events in n minutes
Failure can be either responseElements = {"ConsoleLogin": "Failure"} or responseElements = {"SwitchRole": "Failure"}

```
GET cloudtrail-2020-07-27/_search
{
    "query": {
    "bool": {
      "must": [{"wildcard":{"responseElements.keyword":"*Failure*"}}],
      "filter": [
        {"term": {"eventSource.keyword":"signin.amazonaws.com"}},
        {"term": {"recipientAccountId.keyword":"987654321"}},
        { "range": { "eventTime": { "gte": "2020-07-20T08:00:00.000Z" }}}
      ] 
    }
  },
  "size":0,
  "aggs": {
    "my_count": {
      "terms": {
        "field": "userIdentity.userName.keyword"
          }
        }
    }
}
```


### Example DynamoDB Test Rule
```
{
  "AlertMinimumEventCount": 3,
  "AlertPeriodMinutes": 5,
  "AlertText": "User reached signin failure threshold in account 12345678:\nThe following users caused more than 3 login failures within 5 minutes. ",
  "Description": "Search for users that created signin.amazonaws.com events matching responseElements = {'ConsoleLogin': 'Failure'} or responseElements = {'SwitchRole': 'Failure'} ",
  "ES_Index": "cloudtrail*",
  "LastAggResult": {
    "AKIA4RKH6JM6CBCA3X5U": 1595122200,
    "ASIA4RKH6JM6KFARZXXX": 1595122200
  },
  "LastRun": 1595858028,
  "Query": "{\n    \"query\": {\n    \"bool\": {\n      \"must\": [{\"wildcard\":{\"responseElements.keyword\":\"*Failure*\"}}],\n      \"filter\": [\n        {\"term\": {\"eventSource.keyword\":\"signin.amazonaws.com\"}},\n        {\"term\": {\"recipientAccountId.keyword\":\"987654321\"}},\n        { \"range\": { \"eventTime\": { \"gte\": \"2020-07-20T08:00:00.000Z\" }}}\n      ] \n    }\n  },\n  \"size\":0,\n  \"aggs\": {\n    \"my_count\": {\n      \"terms\": {\n        \"field\": \"userIdentity.userName.keyword\"\n          }\n        }\n    }\n}",
  "RuleId": "Failed user authentication",
  "RuleType": "User activity anomaly",
  "RunScheduleInMinutes": 60
}
```
