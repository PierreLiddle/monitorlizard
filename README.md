<img src="https://raw.githubusercontent.com/awsvolks/monitorlizard/master/Monitor%20Lizard.png" alt="drawing" width="100" align="right"/>

# Monitor Lizard
Cloud native event detection engine for AWS logs stored in Elasticsearch

## What is it?
The purpose of Monitor Lizard is 
...to run threat detection use cases using AWS native solutions without the need of a SIEM

build on [securty data lalke](https://github.com/awsvolks/securitydatalake)

### What is log correlation?

## What is it not?
...it is not a SIEM. It can detect some use cases, but it doesn't have TI lookups or other advanced SIEM features


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
Example:
1. Alert on users that have launched an EC2 instance in production for the first time in 10 days.
	Autoscale happens frequently, but an attacker would do this with a different IAM user for the first time.
2. Alert on users that have created a S3 bucket in the production account


### Use Case 2: Find single events
Find events that include or do not include certain values (regex) within log fields. A rule can define multiple `find` or `missing` conditions.

**Example 1:**
Find EC2 RunInstances events with a specific Tag

**Example 2:**
Find EC2 RunInstances events with a specific Tag missing

**Example 3:**
Find launch EC2 instance events within the production account not performed by a specific role



