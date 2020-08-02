#
# Monitor Lizard - Demo Data Generator
# Version: 08082020
#
# Description: 
#   Write CloudTrail demo data to Elasticsearch
#
# Author:
#   Volker Rath, awsvolks@amazon.com
#
# Date:
#   August 2020
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
DEBUG = True                    # Default: False


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




def writeDemoData(esClient, DemoDataIndex, eventName="CreateUser"):

    global DEBUG
    
    jsonDoc = {
        "eventVersion": "1.05",
        "eventTime": "2020-08-02T03:48:24Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
    
        "userIdentity": {
          "type": "AssumedRole",
          "principalId": "AROA4RKH6JM6LD63WC7LA:awsvolks-Isengard",
          "arn": "arn:aws:sts::861828696892:assumed-role/God/awsvolks-Isengard",
          "accountId": "861828696892",
          "accessKeyId": "TEST EVENT",
          "sessionContext": {
            "sessionIssuer": {
              "type": "Role",
              "principalId": "TEST EVENT",
              "arn": "TEST EVENT",
              "accountId": "861828696892",
              "userName": "God"
            }
            }
        },
        "sourceIPAddress": "0.0.0.0",
        "userAgent": "TEST EVENT",
        "requestParameters": "{\"userName\": \"billybob-cliandconsole\", \"tags\": [{\"key\": \"test\", \"value\": \"true\"}]}",
        "responseElements": "TEST EVENT",
        "requestID": "f0c539ce-7f0e-489e-a89f-32612de519ff",
        "eventID": "TEST EVENT",
        "eventType": "AwsApiCall",
        "recipientAccountId": "861828696892",
        "Enriched": {
          "knownGood": "false",
          "knownBad": "false"
        },
        "geoip": {
          "city_name": "",
          "country_name": "",
          "latitude": "",
          "longitude": "",
          "country_code3": "",
          "continent_code": "",
          "postal_code": "",
          "region_code": "",
          "region_name": "",
          "timezone": ""
        }
      }
    
    retval = esClient.index(index=DemoDataIndex, body=jsonDoc)     
    consoleLog("Added demo document to Elasticsearch index {0}. Doc Id:{1}".format(DemoDataIndex, retval["_id"]),"DEBUG",esLogLevelGv)
    return retval["_id"]


def deleteDemoData(esClient, DemoDataIndex, DocId)
     retval = esClient.index(DemoDataIndex, DocId)

    retval = esClient.index(index=DemoDataIndex, body=jsonDoc)     
    consoleLog("Deleted demo document in Elasticsearch index {0}. Doc Id:{1}".format(DemoDataIndex, DocId),"DEBUG",esLogLevelGv)
        
#
# MAIN
#

def lambda_handler(event, context):
    

    # Connect to Elasticsearch
    esClient = connectES(esEndPointEv)
    consoleLog("lambda_handler : Elasticsearch connection.","DEBUG",esLogLevelGv)  

    
    #
    # Write Demo Data
    #
    
    DemoDataIndex = "cloudtrail-2020.08.02"
    
    DocId = writeDemoData(esClient, DemoDataIndex)
    
    deleteDemoData(esClient, DemoDataIndex, DocId)
     

    
    return {
            'statusCode': 200,
            'body': json.dumps("ok")
        }
        
    

