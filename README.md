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

Another use case could be the detection of triggers originating from decoys services used as a deception mechanism. 

Monitor Lizard can send SNS messages and adds a new document into an Elasticsearch index each time a rule fires.

### But doesn't Amazon GuardDuty do this job already? 
Amazon GuardDuty is a threat detection soluton that utilizes AWS native logs and threat intelligence sources in order to find suspicious events within accounts and workloads such as traffic originating from malicious sources or the deactivation of security controls. GuardDuty is managed by AWS and is focusing on generally applicable threat detection strategies. Monitor Lizard can be used to define customized threat detection rules that are individual to an organisation or even to a workload.


## What is it not?
The security data lake solution in combination with Monitor Lizard provides some correlation features that are typically provided by SIEM solutions but Monitor Lizard. SIEMs are more feature rich and do also utilise threat intelligence to find malicious activities. SIEMs are also geared to consume a large amount of different log types accross the solution stack.

The intention behind Monitor Lizard is not to build another SIEM solution but to provide basic event correlation capabilities for AWS native logs if no SIEM is available.



## Why did we build it?
### Customer struggle with SIEMs 
Organisations struggle with making use out of AWS native logs within SIEMs due to the complex structure (hard to write rules) and the size (commercially difficult to ingest the huge amounts of log data into the SIEM)
SIEMs don't come with a set of canned rules to detect threats within CloudTrail. Many organisations to not have the resources to develop a good threat detection capability with SIEMs because the work that needs to be done to ingest the highly nested JSON logs into a particular SIEM format, the knowledge of what to look for in CloudTrail and the investment to get it done.
Monitor Lizard can be deployed quickly and provides a good baseline capability without large investments. 


### ELK struggles with correlation
The ELK Stack does not come with built-in correlation rules or advanced correlation capabilities, and so it is up to the analyst to use Kibana queries, based on the parsing and processing performed using Logstash, to correlate between events. This is a manual task and ELK is not designed to perform automated log correlation. 


### What is log correlation?
Log correlation compares different events rather than just checking for details within a single event. The most prominent and simple example are multiple failed login events originating from the same IP address.



## Use cases

### Use cases and rules
Monitor Lizard supports multiple use cases (see below). Each use case can run multiple rules or configuration sets. E.g. the use case "Find single event" can have a rule that finds suspicious EC2 events and another rule that looks for suspicious IAM events.

### Tip
Develop operating practices that help you to easier distinguish good from bad events. E.g. by the use of tagging, a clear separation between different account types (prod, test, dev), controlled deployment practices etc.


### [Use Case 1: User activity anomaly](https://github.com/awsvolks/monitorlizard/tree/master/Lambda/UseCase1)
Find users or IP addresses that have performed actions for the first time within n minutes.
Find users that performed an action more then n times within n minutes.

Examples:

1. Alert on users that have launched an EC2 instance in production for the first time in 10 days.
	Autoscale happens frequently, but an attacker would do this with a different IAM user for the first time.
2. Alert on users that have created a S3 bucket or used DynamoDB in the production account for the first time
3. More than 3 user signin failures within 5 minutes (sign in or assume role)

Rule Set:

Rule Id	|	Rule Type	|	Description
----|	----	|----	
Access Denied in Production	|	User activity anomaly	|	Access denied event occured in production account 12345678: The following users caused more than 3 access denied within 5 minutes in any service.
New user created S3 bucket	|	User activity anomaly	|	New user created S3 bucket in production account.
Failed user authentication	|	User activity anomaly	|	User reached signin failure threshold in account 12345678: The following users caused more than 3 login failures within 5 minutes.
Failed authentications from IP	|	User activity anomaly	|	Source IP reached signin failure threshold (any account).
Failed Assume Role	|	User activity anomaly	|	User reached failed assume role threshold in account 12345678: The following users caused more than 3 login failures within 5 minutes.
New users launching EC2 instance	|	User activity anomaly	|	New or infrequent launch EC2 instance event by user in production account: The following IAM users where used for EC2 launch events for the first time within the alert window.
Unauthorized Operation in Production	|	User activity anomaly	|	Unauthorized operation event occured in production account 12345678: The following users caused at least 1 unauthorized error within 5 minutes in any service.


### [Use Case 2: Event anomaly](https://github.com/awsvolks/monitorlizard/tree/master/Lambda/UseCase2)

Find events that include or do not include certain values (regex) within log fields. A rule can define multiple `find` or `missing` conditions.

Examples:

1. Find EC2 RunInstances events with a specific Tag
2. Find EC2 RunInstances events with a specific Tag missing
3. Find launch EC2 instance events within the production account not performed by a specific role

Rule Set:

Rule Id	|	Rule Type	|	Description
----|	----	|----	
IAM role created	|	Event anomaly	|	Created IAM role in production account.
Create IAM user without tag	|	Event anomaly	|	New IAM user created without tag: The following IAM users where created.
MFA deactivated	|	Event anomaly	|	An MFA device has been deactivated and its association has been removed from a user.
Modified IAM Policy	|	Event anomaly	|	Created or modified IAM policy in production account.
Create Programmatic Access Key	|	Event anomaly	|	New IAM programmatic access key created in account 987654321.
EBS snapshort public sharing	|	Event anomaly	|	A EBS snapshot has been shared publicly in the production account.
Bucket policy modification	|	Event anomaly	|	A bucket policy has been changed in the production account.
Modified SG ingress	|	Event anomaly	|	The ingress policy of a specific security group belonging to a sensitive workload has been changed.
Create IAM user	|	Event anomaly	|	New IAM user created: The following IAM users where created.




### [Use Case 3: Login anomaly](https://github.com/awsvolks/monitorlizard/tree/master/Lambda/UseCase3)

Find different login anomalies indicating either brute force or password spray attacks.

Examples:

1. User logs in from different IPs/countries/cities within short time period
2. Multiple users try to login from same IP within short time period

Rule Set:

Rule Id	|	Rule Type	|	Description
----|	----	|----	
Multiple users from same IP	|	Login anomaly	|	Multiple users logged in from same IP within time window
Logins from multiple cities	|	Login anomaly	|	User logged in from different cities within same time window
Logins from multiple countries	|	Login anomaly	|	(optional) User logged in from different countries within same time window
Logins from multiple IPs	|	Login anomaly	|	(optional) User logged in from different IPs within same time window




## How to craft Elasticsearch DLS queries

### Using Kibana

Create your search in Kibana using filters and KQL search expression. Run query. 

Select Inspect and copy the Request into a text editor.

Extract the Query part and test in Kibana Dev tools.