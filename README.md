<img src="https://raw.githubusercontent.com/awsvolks/monitorlizard/master/Monitor%20Lizard.png" alt="drawing" width="100" align="right"/>


# Monitor Lizard
Cloud native event detection engine for AWS logs stored in Elasticsearch

## What is it?
Monitor Lizard runs ontop of the Elasticsearch [securty data lalke](https://github.com/awsvolks/securitydatalake) solution and performs customized event correlation within AWS native logs using AWS native solutions such as AWS Lambda, Amazon DynamoDB, AWS SNS and the Amazon Elasticsearch service for the purpose of threat and anomaly detection.

But doesn't Amazon GuardDuty do this job already?  
Amazon GuardDuty is a threat detection soluton that utilizes AWS native logs and threat intelligence sources in order to find suspicious events within accounts and workloads such as traffic originating from malicious sources or the deactivation of security controls.  
Monitor Lizard can be used to define customized threat detection rules that are individual to an organisation such as finding specific events within the production account that are not performed by a specific role.


### What is log correlation?
Log correlation compares different events rather than just checking for details within a single event. The most prominent and simple example are multiple failed login events from the IP same source.

## What is it not?
The security data lake solution in combination with Monitor Lizard provides some features that are typically provided by SIEM solutions but the functionality of Monitor Lizards event correlation capabilities limited. The intention is not to build a new SIEM solution but to provide basic event correlation without the need of a SIEM.


## Why do I need it?
### Customer struggle with SIEMs 
Organisations struggle with making use out of AWS native logs within SIEMs due to the complex structure (hard to write rules) and the size (commercially difficult to ingest the huge amounts of log data into the SIEM)
SIEMs don't come with a set of canned rules to detect threats within CloudTrail. Many organisations to not have the resources to develop a good threat detection capability with SIEMs because the work that needs to be done to ingest the highly nested JSON logs into a particular SIEM format, the knowledge of what to look for in CloudTrail and the investment to get it done.
Monitor Lizard can be deployed quickly and provides a good baseline capability without large investments. 


### ELK struggles with correlation
The ELK Stack does not come with built-in correlation rules, and so it is up to the analyst to use Kibana queries, based on the parsing and processing performed using Logstash, to correlate between events. This is a manual task and ELK is not designed to perform automated log correlation. 



## Currently supported use cases
### [Use Case 1: User activity anomaly](https://github.com/awsvolks/monitorlizard/tree/master/Lambda/UseCase1)
Find users or IP addresses that have performed actions for the first time within n minutes
Examples:
1. Alert on users that have launched an EC2 instance in production for the first time in 10 days.
	Autoscale happens frequently, but an attacker would do this with a different IAM user for the first time.
2. Alert on users that have created a S3 bucket in the production account


### Use Case 2: Find single events
Find events that include or do not include certain values (regex) within log fields. A rule can define multiple `find` or `missing` conditions.

Examples:
1. Find EC2 RunInstances events with a specific Tag
2. Find EC2 RunInstances events with a specific Tag missing
3. Find launch EC2 instance events within the production account not performed by a specific role



## Backlog

## Use Case #3: “Context anomaly”

User that executes multiple commands within time window such as (

* Change bucket policy and delete bucket (for same bucket)
* CreateUser and CreateAccessKey (for same user)


## Use Case #4:“User activity anomaly v2”
Find first occurrence of user activity but alert only if a particular field value is seen for the first time.

Example 1: User logs in from country he/she hasn’t logged in before (last x days)
Example 2: User assumes role for the first time he/she hasn't used before 
