from hashlib import sha3_384
from operator import ne
import boto3
import json
import uuid
from botocore.exceptions import ClientError
import datetime
import logging
import glob
import os
import time

logger=logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ['REGION']
S3_BUCKET = os.environ['S3_BUCKET']
KMS_KEY_ID = os.environ['KMS_KEY_ID']
SSM_PARAMETER_COUNT = os.environ['SSM_PARAMETER_COUNT']

sechub = boto3.client('securityhub')
s3 = boto3.resource('s3')
ssm = boto3.client('ssm')

def create_filter ():
    day_counter = 365
    now = datetime.datetime.now()
    start_date_to_get_findings = now
    end_date_to_get_findings = now - datetime.timedelta(days=day_counter)
    start_date_to_get_findings = start_date_to_get_findings.replace(
        hour=0, minute=0, second=0, microsecond=0)
    end_date_to_get_findings = end_date_to_get_findings.replace(
        hour=23, minute=59, second=59, microsecond=59)
    
    logger.info("Creating finding filter to get findings from {} to {}...".format(start_date_to_get_findings,end_date_to_get_findings))

    finding_filter = {
                #'UpdatedAt': [
                #    {
                #        'Start': start_date_to_get_findings.strftime('%Y-%m-%dT%H:%M'),
                #        'End': end_date_to_get_findings.strftime('%Y-%m-%dT%H:%M')
                        # 'DateRange': {
                        #     'Value': 1,
                        #     'Unit': 'DAYS'
                        # }
                #    },
                #],
                # "Region": [
                #     {
                #         "Value": REGION,
                #         "Comparison": "EQUALS"
                #     }
                # ],
                #"WorkflowStatus": [
                #    {
                #        "Value": "NEW",
                #        "Comparison": "EQUALS"
                #    },
                #    {
                #        "Value": "NOTIFIED",
                #        "Comparison": "EQUALS"
                #    }
                #],
                # "RecordState": [
                #     {
                #         "Value": "ACTIVE",
                #         "Comparison": "EQUALS"
                #     },
                # ]
            }
    return finding_filter

def get_findings (finding_filter, next_token):
    max_iterator = 50
    results=[]
    logger.info("Running export for Security Hub findings...")
    for x in range(0, max_iterator, 1):
        try:
            response = sechub.get_findings(
            Filters = finding_filter,
            NextToken = next_token,
            MaxResults=100
            )
            results.extend(response["Findings"])
            if "NextToken" in response:
                next_token=response['NextToken']
            else:
                logger.info("NextToken not found. Ending Security Hub finding export.")
                next_token = None
                break
        except ClientError as error_handle:
            if error_handle.response['Error']['Code'] == 'TooManyRequestsException':
                time.sleep(5)
                logger.warning('Catching Security Hub API Throttle...')
                next_token=response['NextToken']
        except Exception as exception_handle:
            logger.error(exception_handle)
            next_token=response['NextToken']
    logger.info("Consolidating {} findings...".format(len(results)))
    consolidated_results = (json.dumps(results))
    return next_token, results, consolidated_results

def sechub_count_value (results):
    logger.info("Adding {} Security Hub findings to export count...".format(len(results)))
    try: 
        existing_value = ssm.get_parameter(
            Name=SSM_PARAMETER_COUNT
        )
        existing_value['Parameter']['Value']
        sechub_count = (int(existing_value['Parameter']['Value'])) + len(results)
        response = ssm.put_parameter(
            Name=SSM_PARAMETER_COUNT,
            Value= str(sechub_count),
            Overwrite=True,
        )
        logger.info("Current Security Hub export count is {}.".format(str(sechub_count)))
    except ClientError as error_handle:
            logger.error(error_handle)
    return sechub_count

def put_obj_to_s3(results, consolidated_results):
    key = datetime.datetime.now().strftime('%Y/%m/%d') + "/security-hub-finding-export" + str(uuid.uuid4()) + ".json"
    logger.info("Exporting {} findings to s3://{}/{}".format(len(results), S3_BUCKET, key))
    max_iterator = 3
    for x in range(0, max_iterator, 1):
        while True:
            try:
                s3.Bucket(S3_BUCKET).put_object(
                Key=key,
                Body=consolidated_results
                )
                logger.info("Successfully exported {} findings to s3://{}/{}".format(len(results), S3_BUCKET, key))
            except ClientError as error_handle:
                    if error_handle.response['Error']['Code'] == 'ConnectTimeoutError':
                        time.sleep(5)
                        logger.warning('Catching Connection Timeout Error...')
                        continue
            except Exception as exception_handle:
                    logger.error(exception_handle)  
            break

def lambda_handler(event, context):
    print (event)
    finding_filter = create_filter()
    if 'Payload' in event:
        next_token = event['Payload']['NextToken']
        logger.info("NextToken {} detected for Security Hub findings.".format(next_token))
    else:
        next_token = ''
        logger.info("NextToken not detected for Security Hub findings.")
    runs = 25
    for a in range(0, runs, 1):
        if (next_token is not None):
            next_token, results, consolidated_results = get_findings(finding_filter, next_token)
            put_obj_to_s3(results, consolidated_results)
            sechub_count = sechub_count_value(results)
        else:
            logger.info("NextToken not found... Ending Security Hub finding export.")
            break
    return {
        'NextToken': next_token,
        'SecHubCount': sechub_count
    }