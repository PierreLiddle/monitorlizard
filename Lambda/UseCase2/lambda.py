#
# Monitor Lizard - Rule2
# Use Case “Find single event”
#
# Version: 28072020
#
# Description: 
#   Event detection for AWS events in Elasticsearch.
#   Example use case: Alert on IAM user creation (without tag|)
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
import re
from boto3.dynamodb.conditions import Key, Attr
from Logger import consoleLog
from datetime import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers  #Installed as sdl-es-python3 layer in AWS Lambda.
from requests_aws4auth import AWS4Auth  #Installed as sdl-awsauth-python3 layer in AWS Lambda.
from functools import reduce
from datetime import datetime


# Globals
DEBUG = True 
TEST_SNS = False                # no execution of any rule, just send a sinple test message
SEND_ALERT = False               # Send or send not SNS alrert message and add document to index MonitorLizardAlerts
TEST_RULE = "Create IAM user"                  # Execute only rule with this rule Id. Ignore LastRun settings. Default is ""
TEST_NOUPDATE = True            # Don't update LastAggResult in DynamoDB
TEST_AlertPeriod = 10000        # Extend alert AlertPeriodMinutes by more minutes for test runs covering a wider data pool



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

    global DEBUG
    
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
        
        Rule_Condition = json.loads(DBresponse["Items"][0]["Rule_Condition"])

    except Exception as E:
        print(E)
        consoleLog("Error reading some of the database values. JSON error?.","ERROR",esLogLevelGv)
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
    # Run Elasticsearch query
    #
   
    result = esClient.search( index=Rule_ES_Index, body=Rule_Query)    
    hits = result["hits"]["total"]["value"]
    
    AlertOccurrences ={}
    QueryTime = int(time.time())
    
    print ("Number of hits: ",hits)
    
    if hits > 0:
        for hit in result["hits"]["hits"]:

            if DEBUG:
                print("-------rule query hit---------")
                print("checking rule condition for this document")
                #print(hit)

            # Test
            '''
            Rule_Condition = {
                "matches": [{
                    "search_field" : "requestParameters",
                    "search_regex" : '.*{"key": "test", "value": "true"}.*',
                    "search_logic" : True
                },{
                    "search_field" : "recipientAccountId",
                    "search_regex" : '861828696892',
                    "search_logic" : True
                }]
            }
            '''
            
            # Check all conditions for this hit
            # Only alert, if all conditions are met
            RuleFired = True
            
            for match in Rule_Condition["matches"]:
                
                search_field = match["search_field"]        # Elasticsearch field
                search_regex = r"{}".format(match["search_regex"])      # regex
                search_logic = match["search_logic"]                    # True or False (Rule fires if regex is a match or not match)
                
                # Convert to boolean value
                if search_logic.lower() == "true":
                    search_logic = True
                else:
                    search_logic = False
    
    
    
                print ("Check if ",search_field," matches ",search_regex," is ",search_logic)
                
                # check if search_field exists
                if search_field in hit["_source"]:
    
                    if hit["_source"][search_field]:
    
                        # check for search_regex 
                        line=str(hit["_source"][search_field])
                        matchObj = re.search( search_regex, line, re.M|re.I)
        
                        if matchObj and search_logic:
                            print(' > condition met. Alert only raised if all conditions match.')
                        else:
                            if not matchObj and not search_logic:
                                print(' > condition met.  Alert only raised if all conditions match.')
                            else:
                                print(' > condition NOT met. No alert for this rule raised.')
                                RuleFired = False
                else:
                    print ("Field ",search_field," not found in Elasticsearch document ")
                
            # Fire rule if all conditions are met
            if RuleFired:
                docId = hit["_id"]
                AlertOccurrences[docId] = QueryTime
        
    
    #
    # Raise alerts
    #
    for AggField in AlertOccurrences:
        
        Message = Rule_AlertText+"\n"+"Document (_id): "+AggField+"\nRule Id: "+RuleId+"\nRule Type: "+RuleType+"\nElasticsearch Index: "+Rule_ES_Index+"\nAlert window: "+str(Rule_AlertPeriodMinutes)+" minutes\n"
        #consoleLog("ALERT MESSAGE:"+Message,"DEBUG",esLogLevelGv)
        
        if SEND_ALERT:
            consoleLog("Send alert for document _id: "+AggField,"INFO",esLogLevelGv)
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
    
    RuleType = "Find single event"

    response = dynamodb_table.scan(
        FilterExpression=Attr('RuleType').eq(RuleType)
    )

    
    if TEST_RULE:
        print( "Executing TEST_RULE only " )
        runRule(esClient, dynamodb_table, sns, TEST_RULE, RuleType)
        return
    
    
    for Rule in response["Items"]:
        
        if Rule["LastRun"]+(Rule["RunScheduleInMinutes"]*60) < int(time.time()):
        
            print("--------------------------")
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
            print( "Skipping SIEM rule "+Rule["RuleId"] +" because recent execution")
    
    
    
     

    
    return {
            'statusCode': 200,
            'body': json.dumps("ok")
        }
        
    

