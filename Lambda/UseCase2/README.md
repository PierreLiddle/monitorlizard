#Use Case “Find single events”

## Introduction

Find simple events such as EC2 launch events in a particular account or
event with complex details such as informatin that that part of a JSON construct within the cloudtrail logs.

**Example 1:**
Find EC2 RunInstances events with a specific Tag

**Example 2:**
Find EC2 RunInstances events with a specific Tag missing

**Example 3:**
Find createUser events with access keys created for user

**Example 4:**
Find any createUser event


## Rule query logic
The query of each rule is defined in the Lucene query language that used in the Kibana Dev-Tools **excluding** the first line `GET cloudtrail*/_search` 

The following example query searches for all users that performed EC2 _RunInstance_ events in a particular account. For test purposes, the date range filter term is still part of this query but is changed (or added) dynamically during every rule execution to greater than {NOW - AlertPeriodMinutes}.

The query should be performed manually in Kibana-Dev tools for test purposes to test the query logic.  

```
GET cloudtrail*/_search     <<< remove when defining rule query in DynamoDB !!!
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
  "size":2,
  "aggs": {
    "my_count": {
      "terms": {
        "field": "userIdentity.arn.keyword"
          }
        }
    }
}
```

## Rule alert logic

New users launching EC2 instance (AlertPeriodInMinutes=3600, AlertMinimumEventCount=1)
> Alert by user on every EC2 launch event if the user hasn't performed this event in the last 60 hours 



