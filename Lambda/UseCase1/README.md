# Use Case “User activity anomaly”

Introduction

Find activities that haven’t been performed by a particular user in the last x days.
Example 1: Autoscale user creates EC2 instances all the time. A malicious user does it for the first time.
Example 2: User logs in from country it hasn’t logged in before (last x days)
Example 3: Accesskey used for the first time in x days (CLI activity)

_Approach_: 

_Search_ 
1. eventSource=EC2 + EventName=createInstance + recipientAccountId=861828696892 + userIdentity.Type!=AWSService
2. eventSource=signin + evenName=ConsoleLogin + recipientAccountId=861828696892 
3. userIdentity.accessKeyId EXISTS

_Group By_
1. userIdentity.arn
2. Country AND userIdentity.arn
3. userIdentity.accessKeyId

Maintain list of [GroupBy] with last event time stamp
Save rule id, number of occurrences by {field}, timestamp
Compare new list with existing list:
Alert on new {rule Id}-{field} occurrence
Alert on existing {rule Id}-{field} entries where old time stamp is older than [alert period]

