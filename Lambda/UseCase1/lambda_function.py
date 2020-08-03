#
# Monitor Lizard - Rule1
#
# Version: 28072020
#
# Description: 
#   Event detection for AWS events in Elasticsearch.
#   Use Case “User activity anomaly”
#   Example use case: Alert on new users that created a S3 bucket in production account
#
# Author:
#   Volker Rath, awsvolks@amazon.com
#
# Date:
#   July 2020
#
# Required Environment Variables:
#   Key : Value
#   DynamoDB    : SIEM
#   ES_AUTH_TYPE    : esl
#   ES_ENDPOINT : es-endpoint-7fy3xguvkfnhczlw3yxqui.us-east-2.es.amazonaws.com
#   ES_LOGIN_ONLY_FOR_ESL_AUTHTYPE  : username
#   ES_LOG_LEVEL    : DEBUG
#   ES_PWD_ONLY_FOR_ESL_AUTHTYPE    : password
#   ES_REGION   : us-east-2
#   SNS_TOPIC_ARN   : arn:aws:sns:us-east-2:987654321:Kibana-Alerts
#


import json
import os
import boto3
import botocore
import urllib3
import time
import requests 
from boto3.dynamodb.conditions import Key, Attr
from Logger import consoleLog
from datetime import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers  #Installed as sdl-es-python3 layer in AWS Lambda.
from requests_aws4auth import AWS4Auth  #Installed as sdl-awsauth-python3 layer in AWS Lambda.
from functools import reduce
from datetime import datetime


# Globals
DEBUG = True                # Default: False
TEST_SNS = False            # no execution of any rule, just send a sinple test message,  Default: False
SEND_ALERT = True           # Send or send not SNS alrert message and add document to index MonitorLizardAlerts,  Default: True
TEST_RULE = ""              # Execute only rule with this rule Id. Ignore LastRun settings, Default ""
TEST_NOUPDATE = False       # Don't update LastAggResult in DynamoDB, Default: False
TEST_AlertPeriod = 0        # Extend alert AlertPeriodMinutes by more minutes for test runs covering a wider data pool, Default: 0
TEST_IGNORE_LASTRUN = False # Run regardless of recent execution,  Default: False

# Set rule type
RuleType = "User activity anomaly"

# Read Environment Variables
esAuthTypeEv = os.environ["ES_AUTH_TYPE"].lower()  #iam or esl, iam required for fine grained access, esl requires Login and Password to be set.
esInternalLoginEv = os.environ["ES_LOGIN_ONLY_FOR_ESL_AUTHTYPE"]  #Elasticsearch internal login, not used with iam.
esInternalPwdEv = os.environ["ES_PWD_ONLY_FOR_ESL_AUTHTYPE"]  #Elasticsearch internal password, not used with iam.
esRegionEv = os.environ["ES_REGION"]  #AWS Region of the Elasticsearch cluster.
esEndPointEv = os.environ["ES_ENDPOINT"]  #Elasticsearch endpoint not including "https://", can be obtained in the AWS Console.
esLogLevelEv = os.environ["ES_LOG_LEVEL"]  #Allows users to increase or decrease log levels, options in ascending criticality are DEBUG, INFO, ERROR. NB: Need to implement properly.
DynamoDBname = os.environ["DynamoDB"]  # Data storage bucket for persistent storage
SnsTopicArn = os.environ["SNS_TOPIC_ARN"]

# Init global Variables
configError = False
esAuthTypeGv = ""
esLogLevelGv = ""
esClient = ""
dynamodb_client = ""
dynamodb_table = ""


#Is a valid log level set.
if esLogLevelEv not in ("DEBUG", "INFO", "ERROR"):
    configError = True
    consoleLog("Environment Variable : ES_LOG_LEVEL must be set to one of \"DEBUG\", \"INFO\" or \"ERROR\".","ERROR","ERROR")
else:
    esLogLevelGv = esLogLevelEv
    consoleLog("Lambda function log level set to {} defined in ES_LOG_LEVEL environment variable.".format(esLogLevelEv),"DEBUG",esLogLevelGv)



#Check region has been set and is valid.
if esRegionEv not in [region['RegionName'] for region in boto3.client('ec2').describe_regions()['Regions']]:
    configError = True
    consoleLog("Environment Variable : ES_REGION is invalid.","ERROR",esLogLevelGv)



#Get AWS signature used in Elasticsearch connection.
esAwsServiceGv = "es"  #AWS Elasticsearch Service
esCredentialsGv = boto3.Session().get_credentials()  #Get AWS Credentials.
esAwsAuthGv = AWS4Auth(esCredentialsGv.access_key, esCredentialsGv.secret_key, esRegionEv, esAwsServiceGv, session_token=esCredentialsGv.token)  #Generate signature.


#Set esAuthTypeGv according to esAuthTypeEv supplied and check.
if esAuthTypeEv.lower() not in ("iam","esl"):
    configError = True
    consoleLog("Environment Variable : ES_AUTH_TYPE must be set to \"iam\" or \"esl\".","ERROR",esLogLevelGv)
    
if esAuthTypeEv.lower() == "esl":
    if(len(esInternalLoginEv) == 0 or len(esInternalPwdEv) == 0):
        configError = True
        consoleLog("Environment Variables : ES_LOGIN_ONLY_FOR_INT_AUTHTYPE and ES_PWD_ONLY_FOR_INT_AUTHTYPE must be set when ES_AUTH_TYPE = esl.","ERROR",esLogLevelGv)
    else:
        esAuthTypeGv = (esInternalLoginEv,esInternalPwdEv)
        consoleLog("Elasticsearch authentication mode set to esl using Elasticsearch internal credentials provided.","DEBUG",esLogLevelGv)

if esAuthTypeEv.lower() == "iam":
    esAuthTypeGv = esAwsAuthGv
    consoleLog("Elasticsearch authentication mode set to iam using AWS Signature.","DEBUG",esLogLevelGv)


#Is a value set for the Elasticsearch endpoint?
if len(esEndPointEv) == 0:
    configError = True
    consoleLog("Environment Variable : ES_ENDPOINT must be set to the endpoint of the elasticsearch cluster, not including https://.","ERROR",esLogLevelGv)



#Connect to Elasticsearch domain.
def connectES(esEndPoint):
    """
    Description: Creates a connection to the Elasticsearch Domain.
    Parameters: esEndPoint - string - The domain endpoint, found in the AWS Elasticsearch Console but not including the https:// prefix.
    """

    consoleLog("Connecting to the ES Endpoint {0}".format(esEndPoint),"DEBUG",esLogLevelGv)
    try:
        esClient = Elasticsearch(
        timeout=120,
        hosts=[{"host": esEndPoint, "port": 443}],
        http_auth=esAuthTypeGv,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        retry_on_timeout=True)
        return esClient
    except Exception as E:
        consoleLog("Unable to connect to Elasticsearch domain : {0}".format(esEndPoint)+" Exception : "+E,"ERROR",esLogLevelGv)
        exit(3)


#
# Run SIEM rule
#

def runRule(esClient, dynamodb_table, sns, RuleId, RuleType):

    # Read SIEM rule from DynamoDB 
    DBresponse = dynamodb_table.query(
        KeyConditionExpression=Key('RuleId').eq(RuleId)&Key('RuleType').eq(RuleType),
    )

    try:
        Rule_ES_Index = DBresponse["Items"][0]["ES_Index"]
        Rule_Query = json.loads(DBresponse["Items"][0]["Query"])       # must include an aggregation
        Rule_LastAggResult = DBresponse["Items"][0]["LastAggResult"]
        Rule_AlertPeriodMinutes = DBresponse["Items"][0]["AlertPeriodMinutes"]
        Rule_AlertText = DBresponse["Items"][0]["AlertText"]
        Rule_Description = DBresponse["Items"][0]["Description"]
        Rule_AlertMinimumEventCount = DBresponse["Items"][0]["AlertMinimumEventCount"]
        Rule_Active = DBresponse["Items"][0]["RuleActive"]
    except Exception as E:
        consoleLog("Error reading some of the database values.","ERROR",esLogLevelGv)
        return    
    
    
    
    #
    # Remove eventTime range filter and replace with new time filter
    #
    query_start_range = int(time.time()) - (Rule_AlertPeriodMinutes*60) - (TEST_AlertPeriod*60)         # unix time
    query_start_date = datetime.utcfromtimestamp(query_start_range).strftime('%Y-%m-%dT%H:%M:%SZ')      # Zulu time
    
    n=-1
    for filter in Rule_Query["query"]["bool"]["filter"]:
        n=n+1
        if "range" in filter:
            if "eventTime" in filter["range"]:
                Rule_Query["query"]["bool"]["filter"].pop(n) 
                
    # set new dateTime range filter
    Rule_Query["query"]["bool"]["filter"].append({'range': {'eventTime': {'gte': query_start_date}}})
    
    consoleLog("Modified date range filter for query: "+str(Rule_Query["query"]["bool"]["filter"]),"DEBUG",esLogLevelGv)  
    
    
    #
    # Read Elasticsearch aggregation query
    #   with newly set time range filter
    #
   
    result = esClient.search( index=Rule_ES_Index, body=Rule_Query)    
    hits = result["hits"]["total"]["value"]
 
    #
    # Iterate through ElasticSearch aggregation result
    #
    
    # GroupValues_current is an array with all aggregated values (group by) and the unix time from this query
    CurrentAggResult = {}
    QueryTime = int(time.time())
    
    # Get aggregation values and add current time
    for customAggName, value in result["aggregations"].items():
        if isinstance(value, (dict, list)):
            bucket = result["aggregations"][customAggName]["buckets"]
            
            for GroupValue in bucket:
                if GroupValue["doc_count"] >= Rule_AlertMinimumEventCount: 
                    consoleLog(GroupValue["key"] + " found at least "+str(Rule_AlertMinimumEventCount)+" times.","DEBUG",esLogLevelGv)
                    CurrentAggResult[GroupValue["key"]] = QueryTime     # current occurence with current time
                else:
                    consoleLog(GroupValue["key"] + " found but did not reach minimum event count limit of "+str(Rule_AlertMinimumEventCount)+" times.","DEBUG",esLogLevelGv)
                
                
    if DEBUG:
        print("Query result from current run (Group values with timestamp:")
        print(CurrentAggResult)
        print("Query result from previous run saved in DynamoDB:")
        print(Rule_LastAggResult)
    

    #
    # Compare current search result with stored results
    #
    
    AlertOccurrences = {}
    NewAggResult_tmp = Rule_LastAggResult
    NewAggResult = {}
    
    for currentAggField in CurrentAggResult:
        if currentAggField in Rule_LastAggResult.keys():
            occurrencerTimeDiff = CurrentAggResult[currentAggField] - Rule_LastAggResult[currentAggField]
            
            # Alert on this new occurrence (new within alert time frame)
            if (occurrencerTimeDiff/60 > Rule_AlertPeriodMinutes):
                AlertOccurrences[currentAggField] = (occurrencerTimeDiff/60 > Rule_AlertPeriodMinutes)
                consoleLog(currentAggField + " found in previous occurrences. Alert because last occurrence was too long ago ","DEBUG",esLogLevelGv)
            
            NewAggResult_tmp[currentAggField] = QueryTime  # includes new and old occurrences (needs clean up later)  
            
        else:
            # Alert on this new occurrence
            consoleLog(currentAggField + " found in current occurrences. Alert because its new","DEBUG",esLogLevelGv) 
            AlertOccurrences[currentAggField] = QueryTime
            NewAggResult_tmp[currentAggField] = QueryTime  # includes new and old occurrences (needs clean up later)
    

    
    #
    # Clean up NewAggResult (remove events older then Rule_AlertPeriodMinutes).  
    #
    
    for AggField in NewAggResult_tmp:
        if (QueryTime - NewAggResult_tmp[AggField]) > Rule_AlertPeriodMinutes:
            consoleLog(AggField + " removed from stored list of occurrences (out of alert window)","DEBUG",esLogLevelGv)
        else:
            # build new list
            NewAggResult[AggField] = NewAggResult_tmp[AggField]
    
    
    if DEBUG:
        print("New list of query results to be stored in DynamoDB")
        for AggField in NewAggResult:
            print (AggField +":"+ str(NewAggResult[AggField]))
        
    
    #
    # Update stored results (NewAggResult)
    #
    
    if not TEST_NOUPDATE:
        consoleLog("Updating database with list of occurrences","INFO",esLogLevelGv)
        response = dynamodb_table.update_item(
            Key={
                'RuleId': RuleId,
                'RuleType': RuleType
            },
            UpdateExpression="set LastAggResult=:l",
            ExpressionAttributeValues={
                ':l': NewAggResult
            },
            ReturnValues="UPDATED_NEW"
        )
    else:
        consoleLog("Skip update of database for new list of occurrences (Test_NOUPDATE=True)","INFO",esLogLevelGv)
    
    
    #
    # Raise alerts
    #
    for AggField in AlertOccurrences:
        
        Message = Rule_AlertText
        Message = Message + "\nDescription: "+Rule_Description
        Message = Message + "\n"+"Alert Value: "+AggField+"\nRule Id: "+RuleId+"\nRule Type: "+RuleType+"\nElasticsearch Index: "+Rule_ES_Index+"\nAlert window: "+str(Rule_AlertPeriodMinutes)+" minutes\n"
        Message = Message + "\nAlert Query: "+Rule_Query
        
        
        
        
        #consoleLog("ALERT MESSAGE:"+Message,"DEBUG",esLogLevelGv)
        
        if SEND_ALERT:
            consoleLog("Send alert for new occurrence: "+AggField,"INFO",esLogLevelGv)
            response = sns.publish(TopicArn=SnsTopicArn,   
                Message=Message,   
            )
        
            # Add alert to Elasticsearch index
            AlertDateTime = datetime.utcfromtimestamp(int(time.time())).strftime('%Y-%m-%dT%H:%M:%SZ')      
    
            jsonDoc = {
                "AlertDateTime":AlertDateTime,
                "Rule_Id":RuleId,
                "Rule_Type":RuleType,
                "Alert_Value":AggField
            }
            retval = esClient.index(index="monitorlizardalerts", body=jsonDoc)     
            consoleLog("Add document to Elasticsearch index MonitorLizardAlerts : {0}".format(retval),"DEBUG",esLogLevelGv)
        else:
            consoleLog("Alerting deactivated.","INFO",esLogLevelGv)
            
    return






        
#
# MAIN
#

def lambda_handler(event, context):
    
    #
    # To do: Run all rule from this type, run only single rule from this type
    #
    #
    
    # Initialize iterator used in bulk load.
    esBulkMessagesGv = []
    esBulkComplianceMessagesGv = []
    
    # Mark start of function execution.
    timerDict = {}
    timerDict["lambda_handler : Started Processing"] = int(time.time())
    consoleLog("lambda_handler : Started Processing @ {0} {1}:{2}:{3}".format(datetime.now().strftime("%Y-%m-%d"),datetime.now().hour,datetime.now().minute,datetime.now().second),"INFO",esLogLevelGv)


    # If any errors are found reading environment variables, don't continue.
    if configError == True:
        consoleLog("lambda_handler : Not executing, configuration error detected.","ERROR",esLogLevelGv)
        return

    # Connect to Elasticsearch
    esClient = connectES(esEndPointEv)
    consoleLog("lambda_handler : Elasticsearch connection.","DEBUG",esLogLevelGv)  

    # Connect to DynamoDB
    dynamodb_client = boto3.resource('dynamodb')
    dynamodb_table = dynamodb_client.Table(DynamoDBname)
    consoleLog("Dynamo table MonitorLizard status = "+dynamodb_table.table_status,"DEBUG",esLogLevelGv)    
    
    # Connect to SNS
    sns = boto3.client('sns')
    
    if TEST_SNS:
        response = sns.publish(TopicArn=SnsTopicArn,   
            Message='Test message from Monitor Lizard',   
        )
        consoleLog("Sent test SNS message.","INFO",esLogLevelGv)  
        return
    
    
    #
    # Execute rules of type "User activity anomaly"
    #
    
    consoleLog("Executing rule type "+RuleType,"INFO",esLogLevelGv) 
    
    response = dynamodb_table.scan(
        FilterExpression=Attr('RuleType').eq(RuleType)
    )

    
    if len(TEST_RULE):
        print( "Executing TEST_RULE only " )
        runRule(esClient, dynamodb_table, sns, TEST_RULE, RuleType)
        return
    
    
    for Rule in response["Items"]:
        print()
        
        if not Rule["RuleActive"]:
            print( "Skipping SIEM rule because rule has been deactivated (RuleActive=false)" )
            continue
    
        if Rule["LastRun"]+(Rule["RunScheduleInMinutes"]*60) < int(time.time()):

            print( "Executing rule: "+Rule["RuleId"] )
 
            runRule(esClient, dynamodb_table, sns, Rule["RuleId"], Rule["RuleType"])
            
            # Updateing SIEM rule last run time stamp
            response = dynamodb_table.update_item(
                Key={
                    'RuleId': Rule["RuleId"],
                    'RuleType': Rule["RuleType"]
                },
                UpdateExpression="set LastRun=:l",
                ExpressionAttributeValues={
                    ':l': int(time.time())
                },
                ReturnValues="UPDATED_NEW"
            )
        else:
            print("--------------------------")
            
            if (TEST_IGNORE_LASTRUN):
                runRule(esClient, dynamodb_table, sns, Rule["RuleId"], Rule["RuleType"])
            else:
                print( "Skipping SIEM rule because of LastRun setting: "+Rule["RuleId"] )
    
    

    
    return {
            'statusCode': 200,
            'body': json.dumps("ok")
        }
        
    

