import logging
import os
import base64
import json
from googleapiclient import discovery

LOG_LEVEL = os.getenv('LOGLEVEL', 'INFO')
logger = logging.getLogger("CIS-1-0-0-5-1-bucket-public-access-remediation-function")
logger.setLevel(logging.getLevelName(LOG_LEVEL))
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

PROJECT_ID = os.getenv("GCP_PROJECT")
GCP_REGION = os.getenv('FUNCTION_REGION')


def google_cloud_function_handler(event, context):
    """
    Google Cloud function for the use case:
        Rule Name: Identities and credentials: Ensure that Cloud Storage bucket is not anonymously or publicly
                   accessible
        Definition: Bucket should not have Policies with [ Members . lAlUsers eq True or Members . AllAuthenticatedUsers
                    eq True ]
    """
    try:
        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))
        for violation in violations.get('violations'):
            project_id = violation.get("account_id", PROJECT_ID)
            region = violation.get("region_name", GCP_REGION)
            bucket_name = violation["resource_id"].split('buckets/')[1]

            logger.info(f'Got event with Project ID: {project_id}, Bucket: {bucket_name} and Region: {region}')
            disable_public_access_of_bucket(bucket_name, project_id, region)

    except Exception as error:
        raise Exception(f'Error occurred while doing remediation of the use case. Reason: {error}') from error


def disable_public_access_of_bucket(bucket_name, project_id, region):
    """
    This function disables public access of the bucket by removing principals ('allUsers' and 'allAuthenticatedUsers')
    from bucket's permission
    :param bucket_name: Name of bucket
    :param project_id: Id of the GCP project
    :param region: Region of bucket
    """

    try:
        service = discovery.build('storage', 'v1')
        is_bucket_public = False
        # get IAM policy of the bucket
        policy = service.buckets().getIamPolicy(bucket=bucket_name).execute()
        logger.debug(f'Response from getIamPolicy method: {policy}')
        bindings = policy['bindings']
        for binding in bindings:
            if 'allAuthenticatedUsers' in binding['members']:
                is_bucket_public = True
                binding['members'].remove('allAuthenticatedUsers')
            if 'allUsers' in binding['members']:
                is_bucket_public = True
                binding['members'].remove('allUsers')

        if is_bucket_public:
            # update IAM policy of the bucket
            response = service.buckets().setIamPolicy(bucket=bucket_name, body=policy).execute()
            logger.debug(f'Response from setIamPolicy method: {response}')
            logger.info(f'Successfully completed remediation for Bucket: {bucket_name} of Project: {project_id}')
        else:
            logger.info(f'Remediation was already completed for Bucket: {bucket_name} of Project: {project_id}')

    except Exception as error:
        logger.exception(
            f'Error occurred while disabling public access of Bucket: {bucket_name}. Reason: {error}. '
            f'Skipping remediation for this bucket')
