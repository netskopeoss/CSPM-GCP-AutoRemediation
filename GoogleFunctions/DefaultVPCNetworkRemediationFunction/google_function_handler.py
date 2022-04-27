import time
import logging
import os
import json
import base64
from googleapiclient import discovery, errors

LOG_LEVEL = os.getenv('LOGLEVEL', 'INFO')
logger = logging.getLogger("CIS-1-0-0-3-1-DefaultVPCNetworkRemediationFunction")
logger.setLevel(logging.getLevelName(LOG_LEVEL))
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

PROJECT_ID = os.getenv("GCP_PROJECT")
GCP_REGION = os.getenv('FUNCTION_REGION')


def google_cloud_function_handler(event, context):
    """
    Google Cloud function for the use case:
        Rule Name: Communications and control network protection: Ensure the default network does not exist in a project
        Definition: VPC should not have Name eq "default" and AutoCreateSubnetworks eq True
    """
    try:
        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))
        for violation in violations.get('violations'):
            project_id = violation.get("account_id", PROJECT_ID)
            region = violation.get("region_name", GCP_REGION)
            network = violation["resource_id"].split('networks/')[1]

            logger.info(f'Got event with Project ID: {project_id}, VPC Network: {network} and Region: {region}')
            if network == "default":  # check with Default
                delete_default_vpc_network(network, project_id)
            else:
                logger.error(f'Given VPC Network: {network} is not default. Skipping remediation of this VPC Network')

    except Exception as error:
        raise Exception(f'Error occurred while doing remediation of the use case. Reason: {error}') from error


def delete_default_vpc_network(network, project_id):
    """
    This function deletes default VPC network
    :param network: Name of VPC Network
    :param project_id: Id of the project
    """
    try:
        service = discovery.build('compute', 'v1')
        # delete default VPC Network.
        response = service.networks().delete(project=project_id, network=network).execute()
        logger.debug(f'response from delete call : {response}')
        operation = response['name']
        status = wait_for_operation_to_complete(service, project_id, operation)
        if status == "DONE":
            logger.info(f'Successfully deleted default VPC Network of Project: {project_id}')
        elif status == "Timeout":
            logger.warning(f'Remediation not completed. Reason - Timed out while waiting for operation: '
                           f'{operation} to be completed.')

    except errors.HttpError as http_error:
        error_json = json.loads(http_error.content).get('error').get('errors')[0]
        reason = error_json.get("reason")
        message = error_json.get("message")
        if reason == "resourceNotReady":
            logger.error(f"Error occurred while remediation. Another VPC network operation is running"
                         f" for default network. Reason: {message}")
        elif reason == "notFound":
            logger.error(f"It seems default VPC Network does not present for project: {project_id}. Reason: {message}")
        else:
            logger.exception(f'Error occurred while deleting default VPC Network. Reason: {http_error}')

    except Exception as error:
        logger.exception(f'Error occurred while deleting default VPC Network. Reason: {error}')


def wait_for_operation_to_complete(service, project, operation):
    """
    Wait for the operation to complete
    :param service: compute service object
    :param project: Id of the project
    :param operation: Name of the executed operation to wait for
    """
    try:
        logger.info(f'Waiting for operation to finish...')
        for retry in range(1, 6):
            result = service.globalOperations().get(project=project, operation=operation).execute()
            logger.debug(f'response from get operation call: {result}')
            if "error" in result:
                raise Exception(result["error"])
            status = result['status']
            if status == 'DONE':
                logger.info(f'Operation status: {status}')
                return status
            else:
                logger.info(f'Operation status: {status}. Retrying {retry}/5')
                time.sleep(20)
        return "Timeout"

    except Exception as error:
        logger.exception(f'Error occurred while waiting for {operation} to be completed. Error: {error}. '
                         f'Skipping remediation.')
