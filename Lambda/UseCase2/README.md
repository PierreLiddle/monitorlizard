# Use Case “Event anomaly”

## Introduction

Find simple events such as EC2 launch events in a particular account or
event where complex details are parsed using regular expressions.

**Example 1:**
Find EC2 RunInstances events with a specific tag missing

**Example 2:**
Find any createUser events within a specific account with missing tags.

## Tip
Use Kibana to generate template for the query DSL. //
Run query, click "Discover", click "Inspect", copy query.


## Rule query logic (Rule Field: Query)

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

## Rule alert logic (Rule Field: Rule_Condition)

The rule fires, if the query result is matched with the alert logic. The alert logic can contain zero or multiple regex expressions that need to match for the rule to fire.

Example:

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

If all returned docuements of a query should result in the rule fireing, the following "match all" statement needs to be set in the Rule_Condition field:

```
{ "matches": [] }
```


