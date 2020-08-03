# Tips for analyzing Cloudtrail

## Generic
Search (and aggregate) by unique value `userIdentity.arn`. Don't use `userIdentity.accessKeyId` which is a temporary key name.


## EC2 (eventSource:ec2.amazonaws.com)
There is no EC2 event `CreateInstance`, only `RunInstances`

Newly created security group with open ports create event with eventName `AuthorizeSecurityGroupIngress`. Details provided in the field requestParameters.


Add and remove permission for sharing a snapshot. Only change is 'add' or 'remove' in request parameters):

```
eventName: ModifySnapshotAttribute
requestParameters: {"snapshotId": "snap-0e8416a111e63bc9d", "createVolumePermission": {"remove": {"items": [{"group": "all"}]}}, "attributeType": "CREATE_VOLUME_PERMISSION"}
```




## VPC (eventSource:ec2.amazonaws.com)

eventName:AuthorizeSecurityGroupIngress in eventSource:ec2.amazonaws.com is created when a security group is used with open ingress ports as part of an instance launch or security group change


## IAM (eventSource:iam.amazonaws.com)
Delete events (eventName): DeleteLoginProfile, DeleteAccessKey, DeleteUser

User creation event:

```
eventName=CreateUser
requestParameters= {"userName": "billybob-programmatic", "tags": [{"key": "test", "value": "true"}]}

responseElements={"user": {"path": "/", "userName": "billybob-programmatic", "userId": "AIDA4RKH6JM6H67H77GGP", "arn": "arn:aws:iam::861828696892:user/billybob-programmatic", "createDate": "Jul 28, 2020 3:47:25 AM", "tags": [{"key": "test", "value": "true"}]}}
userIdentity.sessionContext.sessionIssuer.arn=arn:aws:iam::861828696892:role/God
```

Programmatic access key has been created for IAM user:

```
eventName=CreateAccessKey
requestParameters= {"userName": "billybob-programmatic"}

responseElements={"accessKey": {"userName": "billybob-programmatic", "accessKeyId": "AKIA4RKH6JM6MJTEDLFP", "status": "Active", "createDate": "Jul 28, 2020 3:47:26 AM"}}
userIdentity.sessionContext.sessionIssuer.arn=arn:aws:iam::861828696892:role/God
```

Add user to group

```
eventName=AddUserToGroup
requestParameters={"groupName": "TrustToVolkersAccount", "userName": "billybob-console"}
```

Attach user policy

```
eventName=AttachUserPolicy
requestParameters={"userName": "billybob-programmatic", "policyArn": "arn:aws:iam::aws:policy/AlexaForBusinessFullAccess"}
```

Change IAM policy  
request parameters contain new policy statement (not the delta to the previous version)

```
eventName=CreatePolicyVersion
requestParameters={"policyArn": "arn:aws:iam::861828696892:policy/S3FullAccessVolkerRathTestBucket", "policyDocument": "{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"VisualEditor0\",\n            \"Effect\": \"Allow\",\n            \"Action\": \"s3:*\",\n            \"Resource\": \"arn:aws:s3:::volkertestbucket\"\n        }\n    ]\n}", "setAsDefault": true}
```

Create a new IAM role

```
eventName: CreateRole	
requestParameters: {"roleName": "TESTROLE", "assumeRolePolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"glue.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}", "description": "Allows Glue to call AWS services on your behalf. ", "tags": [{"key": "TEST", "value": "TESTValue"}]}
```