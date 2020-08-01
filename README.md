<img src="https://raw.githubusercontent.com/awsvolks/monitorlizard/master/Monitor%20Lizard.png" alt="drawing" width="100" align="right"/>


# Monitor Lizard
Cloud native event detection engine for AWS logs stored in Elasticsearch

## What is it?
Monitor Lizard runs ontop of the Elasticsearch [securty data lalke](https://github.com/awsvolks/securitydatalake) solution and performs customized event correlation within AWS native logs using AWS native solutions such as AWS Lambda, Amazon DynamoDB, AWS SNS and the Amazon Elasticsearch service for the purpose of threat and anomaly detection.

The main idea behind this solution is to find events that look legit but are suspicious. These events are called "known unknowns" by security analysts and are typically used for malwareless "living of the land" attacks. 

Examples:

1. Many EC2 instances are launched within the production account either by the role that is used by the deployment pipeline or by AWS as part of an autoscaling event. It is suspicious if user Bob would launch an EC2 instance manually for the first time even if it would be perfectly fine if Bob manually launches instances in the test/dev account. 

2. Another example includes the creation of AWS services and users with a malicious intent. Attackers typically don't apply all tags to EC2 instances because they don't want them to show up in a particular billing category. So instances without a billing related tag are suspicious. 

3. New IAM users with programmatic access keys should be monitored in any way. Create user events and create access key events are two different events in CloudTrail. Both need to considered in combination.

4. For static and very sensitive environments, all create, modify and delete events (eventName:Create\*, Update\*, Delete\*, Stop\*) can be monitored.



But doesn't Amazon GuardDuty do this job already?  
Amazon GuardDuty is a threat detection soluton that utilizes AWS native logs and threat intelligence sources in order to find suspicious events within accounts and workloads such as traffic originating from malicious sources or the deactivation of security controls. Monitor Lizard can be used to define customized threat detection rules that are individual to an organisation such as finding specific events within the production account that are not performed by a specific role.


### What is log correlation?
Log correlation compares different events rather than just checking for details within a single event. The most prominent and simple example are multiple failed login events originating from the same IP address.

### Use cases and rules
Monitor Lizard supports multiple use cases (see below). Each use case can run multiple rules or configuration sets. E.g. the use case "Find single event" can have a rule that finds suspicious EC2 events and another rule that looks for suspicious IAM events.

### Alerting
Monitor Lizard can send SNS messages and add a new document into an Elasticsearch index each time a rule fires.

### Tip
Develop operating practices that help you to easier distinguish good from bad events. E.g. by the use of tagging, a clear separation between different account types (prod, test, dev), controlled deployment practices etc.

## What is it not?
The security data lake solution in combination with Monitor Lizard provides some correlation features that are typically provided by SIEM solutions but Monitor Lizard. SIEMs are more feature rich and do also utilise threat intelligence to find malicious activities. The intention behind this solution is not to build a new SIEM solution but to provide basic event correlation capabilities if no SIEM is available.


## Why did we build it?
### Customer struggle with SIEMs 
Organisations struggle with making use out of AWS native logs within SIEMs due to the complex structure (hard to write rules) and the size (commercially difficult to ingest the huge amounts of log data into the SIEM)
SIEMs don't come with a set of canned rules to detect threats within CloudTrail. Many organisations to not have the resources to develop a good threat detection capability with SIEMs because the work that needs to be done to ingest the highly nested JSON logs into a particular SIEM format, the knowledge of what to look for in CloudTrail and the investment to get it done.
Monitor Lizard can be deployed quickly and provides a good baseline capability without large investments. 


### ELK struggles with correlation
The ELK Stack does not come with built-in correlation rules or advanced correlation capabilities, and so it is up to the analyst to use Kibana queries, based on the parsing and processing performed using Logstash, to correlate between events. This is a manual task and ELK is not designed to perform automated log correlation. 



## Use cases
### [Use Case 1: User activity anomaly](https://github.com/awsvolks/monitorlizard/tree/master/Lambda/UseCase1)
Find users or IP addresses that have performed actions for the first time within n minutes.
Find users that performed an action more then n times within n minutes.

Examples:

1. Alert on users that have launched an EC2 instance in production for the first time in 10 days.
	Autoscale happens frequently, but an attacker would do this with a different IAM user for the first time.
2. Alert on users that have created a S3 bucket or used DynamoDB in the production account for the first time
3. More than 3 user signin failures within 5 minutes (sign in or assume role)





### [Use Case 2: Event anomaly] (https://github.com/awsvolks/monitorlizard/tree/master/Lambda/UseCase2)
Find events that include or do not include certain values (regex) within log fields. A rule can define multiple `find` or `missing` conditions.

Examples:

1. Find EC2 RunInstances events with a specific Tag
2. Find EC2 RunInstances events with a specific Tag missing
3. Find launch EC2 instance events within the production account not performed by a specific role



## Backlog

### Use Case #3: “Event correlation”

User that executes multiple commands within time window such as (

* Change bucket policy and delete bucket (for same bucket)
* CreateUser and CreateAccessKey (for same user)



### Use Case #4:“User activity anomaly v2”
Find first occurrence of user activity but alert only if a particular field value is seen for the first time.

Example 1: User logs in from country he/she hasn’t logged in before (last x days)
Example 2: User assumes role for the first time he/she hasn't used before 
