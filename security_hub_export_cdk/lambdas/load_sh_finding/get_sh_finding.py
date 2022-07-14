import boto3
import json
import uuid
from botocore.exceptions import ClientError
import datetime
import logging
import os
import time

logger=logging.getLogger()
logger.setLevel(logging.INFO)

S3_BUCKET = os.environ['S3_BUCKET']
SSM_PARAMETER_COUNT = os.environ['SSM_PARAMETER_COUNT']

sechub = boto3.client('securityhub')
s3 = boto3.resource('s3')
ssm = boto3.client('ssm')

def create_filter (date_filter):
    converted_string_date = datetime.datetime.strptime(date_filter, '%Y-%m-%dT%H:%M:%S.%fZ')
    day_counter = 90
    updatedat_end = str(converted_string_date.isoformat()[:-3]+'Z')
    updatedat_start = str((converted_string_date - datetime.timedelta(days=day_counter)).isoformat()[:-3]+'Z')
    logger.info("Creating finding filter to get findings from {} to {}...".format(updatedat_start,updatedat_end))

    finding_filter = {
                'UpdatedAt': [
                    {
                        'Start': updatedat_start,
                        'End': updatedat_end
                    },
                ],
                 "RecordState": [
                     {
                         "Value": "ACTIVE",
                         "Comparison": "EQUALS"
                     },
                 ]
            }
    return finding_filter

def get_findings (sechub, finding_filter, next_token):
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
    key = datetime.datetime.now().strftime('%Y/%m/%d/%H') + "/security-hub-finding-export" + str(uuid.uuid4()) + ".json"
    try:
        logger.info("Exporting {} findings to s3://{}/{}".format(len(results), S3_BUCKET, key))
        response = s3.Bucket(S3_BUCKET).put_object(
        Key=key,
        Body=consolidated_results
        )
        logger.info("Successfully exported {} findings to s3://{}/{}".format(len(results), S3_BUCKET, key))
    except ClientError as error_handle:
            if error_handle.response['Error']['Code'] == 'ConnectTimeoutError':
                time.sleep(5)
                logger.warning('Catching Connection Timeout Error...')
    except Exception as exception_handle:
            logger.error(exception_handle)  

def lambda_handler(event, context):
    print (event)
    if 'Payload' in event:
        next_token = event['Payload']['NextToken']
        date_filter = event['Payload']['StartDate']
        logger.info("NextToken {} detected for Security Hub findings.".format(next_token))
    else:
        next_token = ''
        date_filter=event['StartDate']
        logger.info("NextToken not detected for Security Hub findings.")
    finding_filter = create_filter(date_filter)
    runs = 25
    for a in range(0, runs, 1):
        if (next_token is not None):
            next_token, results, consolidated_results = get_findings(sechub, finding_filter, next_token)
            put_obj_to_s3(results, consolidated_results)
            sechub_count = sechub_count_value(results)
        else:
            logger.info("NextToken not found... Ending Security Hub finding export.")
            break
    return {
        'NextToken': next_token,
        'SecHubCount': sechub_count,
        'StartDate': date_filter
    }