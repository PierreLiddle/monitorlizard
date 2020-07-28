# Monitor Lizard
Event detector engine for AWS logs stored in Elasticsearch


## Currently supported use cases
### Use Case 1: User activity anomaly
Find users or IP addresses that have performed actions for the first time within n minutes
Example:
1. Alert on users that have launched an EC2 instance in production for the first time in 10 days.
	Autoscale happens frequently, but an attacker would do this with a different IAM user for the first time.
2. Alert on users that have created a S3 bucket in the production account


### Use Case 2: Find single events
Find events that include or do not include certain values within text or JSON fields.

**Example 1:**
Find EC2 RunInstances events with a specific Tag

**Example 2:**
Find EC2 RunInstances events with a specific Tag missing

**Example 3:**
Find launch EC2 instance events 



