# Use Case “Find single events”

## Introduction

Find simple events such as EC2 launch events in a particular account or
event where complex details are parsed using regular expressions.

**Example 1:**
Find EC2 RunInstances events with a specific tag missing

**Example 2:**
Find any createUser events within a specific account with missing tags.


## Rule query logic

The following example query searches for all create user events. The alert logic is used to filter out users who were created without a specific tag within a specific account.

For test purposes, the date range filter term is still part of this query but is changed (or added) dynamically during every rule execution to greater than {NOW - AlertPeriodMinutes}.

The query should be performed manually in Kibana-Dev tools for test purposes to test the query logic.  


```
{
    "_source": {
        "includes": ["eventTime", "recipientAccountId","eventSource", "eventName", "requestParameters"]},
    "query": {
    "bool": {
      "filter": [
        {"term": {"eventName.keyword":"CreateUser"}},
        {"term": {"recipientAccountId.keyword":"861828696892"}},
        { "range": { "eventTime": { "gte": "2020-07-25T08:00:00.000Z" }}}
      ] 
    }
  }
}
```

## Rule alert logic

Search for all create user events (query logic) that were created without a specific tag within a specific account. 

```
{
    "matches": [{
        "search_field" : "requestParameters",
        "search_regex" : '.*{"key": "test", "value": "true"}.*',
        "search_logic" : False
    },{
        "search_field" : "recipientAccountId",
        "search_regex" : '861828696892',
        "search_logic" : True
    }]
}
```
  
this needs to be stored in DynamoDB in the following format (Boolean values in double quotes and special characters in values masked with \\:

```   
{
    "matches": [{
        "search_field" : "requestParameters",
        "search_regex" : ".*{.*\\"key\\".*:.* \\"test\\", \\"value\\".*:.* \\"true\\".*",
        "search_logic" : "False"
    },{
        "search_field" : "recipientAccountId",
        "search_regex" : "861828696892",
        "search_logic" : "True"
    }]
}
``` 



## Example 4



```
{
    "_source": {
        "includes": ["eventTime", "eventSource", "eventName", "requestParameters"]},
    "query": {
    "bool": {
      "must": [
        {
          "wildcard": {
            "eventName.keyword": "CreateUser"
          }
        }
      ],
      "filter": [
        {"term": {"eventSource.keyword":"iam.amazonaws.com"}},
        {"term": {"recipientAccountId.keyword":"861828696892"}},
        { "range": { "eventTime": { "gte": "2020-07-25T08:00:00.000Z" }}}
      ] 
    }
  }
}
```

