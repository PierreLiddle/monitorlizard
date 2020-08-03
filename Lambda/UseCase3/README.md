# Use Case “Login anomaly”

## Introduction

Find login anomalies. 

**Example 1:**
User logs in from different IPs/cities/countries in the same time window.

**Example 2:**
Different user login requests come from same IP.




## Rule query logic (Rule Field: Query)

Rule "User activity anomaly" uses a single level grouping to find anomalies e.g. count by individual field value.  
This rule uses two layer or nested grouping e.g. group by field one. Within field one, group by field two. Count all field two. 

Example below counts all different countries addresses for each different users.

```
{    
  "query": {
    "bool": {
      "must": [{"match":{"eventName.keyword":"ConsoleLogin"}}],
      "filter": [
        { "range": { "eventTime": { "gte": "2020-07-20T08:00:00.000Z" }}}
      ] 
    }
  },
  "size": 0,
  "aggs": {
    "agg1": {
      "terms": {
        "field": "userIdentity.arn.keyword"
      },
      "aggs": {
        "agg2": {
          "terms": {
            "field": "geoip.country_name.keyword"
          }        
        }
      }
    }
  }
}
```

Example output: One user Billybob logged in from two countries within the search time range.

```
"aggregations" : {
    "agg1" : {
      "doc_count_error_upper_bound" : 0,
      "sum_other_doc_count" : 0,
      "buckets" : [
        {
          "key" : "arn:aws:sts::861828696892:assumed-role/Admin/Billybob",
          "doc_count" : 17,
          "agg2" : {
            "doc_count_error_upper_bound" : 0,
            "sum_other_doc_count" : 0,
            "buckets" : [
              {
                "key" : "United States",
                "doc_count" : 3
              },
              {
                "key" : "Australia",
                "doc_count" : 1
              }
            ]
          }
        }
      ]
    }
  }
```
