import gzip
import json
import base64
import re
import os
import boto3
import botocore
import urllib3
import time
import requests 
from boto3.dynamodb.conditions import Key
from Logger import consoleLog
from datetime import datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers  #Installed as sdl-es-python3 layer in AWS Lambda.
from requests_aws4auth import AWS4Auth  #Installed as sdl-awsauth-python3 layer in AWS Lambda.
from functools import reduce


# Globals
DEBUG = False 
TEST_SNS = False    # no execution, just send a test message
TEST_RULE = "Test"  # Execute only rule with this rule Id instead of all rules of rule type "User activity anomaly"


# Elasticsearch Domain
ES_ENDPOINT = 'search-canva-gpqk7fy3xguvkfnhczlw3yxqui.us-east-2.es.amazonaws.com'
ES_INDEX = 'config'


# Environment Variables
esAuthTypeEv = os.environ["ES_AUTH_TYPE"].lower()  #iam or esl, iam required for fine grained access, esl requires Login and Password to be set.
esInternalLoginEv = os.environ["ES_LOGIN_ONLY_FOR_ESL_AUTHTYPE"]  #Elasticsearch internal login, not used with iam.
esInternalPwdEv = os.environ["ES_PWD_ONLY_FOR_ESL_AUTHTYPE"]  #Elasticsearch internal password, not used with iam.
esRegionEv = os.environ["ES_REGION"]  #AWS Region of the Elasticsearch cluster.
esEndPointEv = os.environ["ES_ENDPOINT"]  #Elasticsearch endpoint not including "https://", can be obtained in the AWS Console.
esLogLevelEv = os.environ["ES_LOG_LEVEL"]  #Allows users to increase or decrease log levels, options in ascending criticality are DEBUG, INFO, ERROR. NB: Need to implement properly.
DynamoDBname = os.environ["DynamoDB"]  # Data storage bucket for persistent storage

#Configuration error found variable, initialized as False.
configError = False

#Global Variables
esAuthTypeGv = ""
esInternalLoginGv = ""
esInternalPwdGv = ""
esRegionGv = ""
esEndPointGv = ""
esIndexGv = ""
esLogLevelGv = ""



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
        

def lambda_handler(event, context):
    
    # Initialize iterator used in bulk load.
    esBulkMessagesGv = []
    esBulkComplianceMessagesGv = []
    
    # Mark start of function execution.
    timerDict = {}
    timerDict["lambda_handler : Started Processing"] = time.time()
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
    
    # read SIEM rule from DynamoDB 
    DBresponse = dynamodb_table.query(
        KeyConditionExpression=Key('RuleId').eq("Test")&Key('RuleType').eq('User activity anomaly'),
    )

    index = DBresponse["Items"][0]["Index"]
    RuleQuery = json.loads(DBresponse["Items"][0]["Query"])       # must include an aggregation
    LastAggResult = json.loads(DBresponse["Items"][0]["LastAggResult"])
    AlertPeriodMinutes = DBresponse["Items"][0]["AlertPeriodMinutes"]
    AlertText = DBresponse["Items"][0]["AlertText"]
    
    #
    # read elasticsearch aggregation query
    #
   
    result = esClient.search( index=index, body=RuleQuery)    
    hits = result["hits"]["total"]["value"]
    bucket = result["aggregations"]["my_count"]["buckets"]
    
    
    #
    # Iterate through ElasticSearch aggregation result
    #
    
    # GroupValues_current is an array with all aggregated values (group by) and the unix time from this query
    CurrentAggResult = {}
    QueryTime = int(time.time())
    
    # deal with custom aggregation name
    for customAggName, value in result["aggregations"].items():
        if isinstance(value, (dict, list)):
            bucket = result["aggregations"][customAggName]["buckets"]
            
            for GroupValue in bucket:
                CurrentAggResult[GroupValue["key"]] = QueryTime
                
    
    print(CurrentAggResult)
    print(LastAggResult)
    

    #
    # Compare current search result with stored results
    #
    
    AlertOccurrences = {}
    NewAggResult_tmp = LastAggResult
    NewAggResult = {}
    
    for currentAggField in CurrentAggResult:
        if currentAggField in LastAggResult.keys():
            occurrencerTimeDiff = CurrentAggResult[currentAggField] - LastAggResult[currentAggField]
            consoleLog(currentAggField + " found in previous occurrences. Time difference is "+str(occurrencerTimeDiff),"DEBUG",esLogLevelGv)
            if (occurrencerTimeDiff/60 > AlertPeriodMinutes):
                AlertOccurrences[currentAggField] = (occurrencerTimeDiff/60 > AlertPeriodMinutes)
            
            NewAggResult_tmp[currentAggField] = QueryTime  # includes new and old occurrences (needs clean up later)  
            
        else:
            consoleLog(currentAggField + " is a new occurrence","DEBUG",esLogLevelGv) 
            AlertOccurrences[currentAggField] = QueryTime
            NewAggResult_tmp[currentAggField] = QueryTime  # includes new and old occurrences (needs clean up later)
    

    
    #
    # Clean up NewAggResult (events older then AlertPeriodMinutes).  
    #
    
    for AggField in NewAggResult_tmp:
        if (QueryTime - NewAggResult_tmp[AggField]) > AlertPeriodMinutes:
            consoleLog(AggField + " removed from stored list of occurrences (out of alert window)","DEBUG",esLogLevelGv)
        else:
            # build new list
            NewAggResult[AggField] = NewAggResult_tmp[AggField]
    
    
    
    for AggField in NewAggResult:
        print ("New list: "+AggField)
        
    
    #
    # Update stored results (NewAggResult)
    #
    
    #
    # Raise alerts
    #
        
    # AlertText, AlertOccurrences
        
    return result
    

