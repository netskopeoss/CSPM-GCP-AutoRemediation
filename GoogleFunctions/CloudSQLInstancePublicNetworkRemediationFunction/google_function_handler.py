import time
import logging
import os
import json
import base64
from googleapiclient import discovery, errors

LOG_LEVEL = os.getenv('LOGLEVEL', 'INFO')
logger = logging.getLogger("CIS-1-0-0-6-2-SQLInstancePublicNetworkRemediationFunction")
logger.setLevel(logging.getLevelName(LOG_LEVEL))
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

PROJECT_ID = os.getenv("GCP_PROJECT")
GCP_REGION = os.getenv('FUNCTION_REGION')


def google_cloud_function_handler(event, context):
    """
    Google Cloud function for the use case:
        Rule Name: Identities and credentials: Ensure that Cloud SQL database Instances are not open to the world
        Definition: SqlInstance should not have Settings.IpConfiguration.AuthorizedNetworks with [ CIDR eq 0.0.0.0/0 ]
    """
    try:
        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))
        for violation in violations.get('violations'):
            project_id = violation.get("account_id", PROJECT_ID)
            region = violation.get("region_name", GCP_REGION)
            instance = violation["resource_id"].split('sqlInstances/')[1]

            logger.info(f'Got event with Project ID: {project_id}, Cloud SQL Instance: {instance} '
                        f'and Region: {region}')
            disable_public_access_cloud_sql_database_instance(instance, project_id, region)

    except Exception as error:
        raise Exception(f'Error occurred while doing remediation of the use case. Reason: {error}') from error


def disable_public_access_cloud_sql_database_instance(instance, project_id, region):
    """
    This function removes public network from Cloud SQL Database Instance
    :param instance: Name of Cloud SQL Database Instance
    :param project_id: Id of the project
    :param region: Region of Cloud SQL Database Instance
    """
    try:
        service = discovery.build('sqladmin', 'v1')
        # get metadata of a Cloud SQL instance.
        instance_metadata = service.instances().get(project=project_id, instance=instance).execute()
        logger.debug(f'response from get call : {instance_metadata}')
        authorized_networks = instance_metadata['settings']['ipConfiguration']['authorizedNetworks']
        # Considering only networks which do not have the value="0.0.0.0/0"
        updated_authorized_networks = [network for network in authorized_networks if not
                                       (network['value'] == '0.0.0.0/0')]
        if int(len(authorized_networks)) > int(len(updated_authorized_networks)):
            # Update metadata of a Cloud SQL instance.
            updated_patch = {"settings": {"ipConfiguration": {"authorizedNetworks": updated_authorized_networks}}}
            update_instance_metadata(service, project_id, instance, updated_patch, region)
        else:
            logger.info(f'Remediation was already completed for Cloud SQL Instance: {instance} of Project: '
                        f'{project_id} and Region: {region}')

    except Exception as error:
        logger.exception(f'Error occurred while doing remediation for Cloud SQL Instance: {instance} of Project: '
                         f'{project_id} and Region: {region}. Skipping remediation for this instance. Reason: {error}')


def update_instance_metadata(service, project_id, instance, instance_metadata, region):
    """
    This function Updates cloud SQL instance metadata
    :param service: compute service object
    :param project_id: Id of the project
    :param instance: Cloud SQL Instance Name
    :param instance_metadata: Metadata of cloud SQL instance
    :param region: Region of cloud SQL instance
    """
    for retry in range(1, 4):
        try:
            response = service.instances().patch(project=project_id, instance=instance,
                                                 body=instance_metadata).execute()
            logger.info(f'Update call executed')
            logger.debug(f'response from update call : {response}')
            operation = response['name']
            # Wait for update operation to be completed
            status = wait_for_operation_to_complete(service, project_id, operation)
            if status == "DONE":
                logger.info(f'Successfully completed remediation for Cloud SQL Instance: {instance} of '
                            f'Project: {project_id} and Region: {region}')
            elif status == "Timeout":
                logger.warning(f'Timed out while waiting for operation: {operation} to be completed. '
                               f'Skipping remediation for the Cloud SQL Instance: {instance} of Project: {project_id} '
                               f'and Region: {region}')
            break
        except errors.HttpError as http_err:
            error_json = json.loads(http_err.content).get('error').get('errors')[0]
            reason = error_json.get("reason")
            if http_err.resp.status == 409 and reason == "operationInProgress":
                logger.warning(f'The operation failed because another operation was already in progress. '
                               f'Retrying {retry}/3')
                if retry != 3:
                    # If this is not last retry then wait for few seconds.
                    time.sleep(25)
                else:
                    logger.exception(f'Remediation is not completed successfully for Cloud SQL Instance: {instance}. '
                                     f'Reason: Max retires exceeded. Error: {http_err}')
            else:
                logger.exception(f'Error occurred while calling patch update API. Error: {http_err}')
                break
        except Exception as error:
            logger.exception(f'Error occurred while updating Cloud SQL Instance: {instance}. Reason: {error}. '
                             f'Skipping remediation for this instance')
            break


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
            result = service.operations().get(project=project, operation=operation).execute()
            logger.debug(f'response from get operation call : {result}')
            if "error" in result:
                raise Exception(result["error"])
            status = result['status']
            if status == 'DONE':
                logger.info(f'Operation status: {status}')
                return status
            else:
                logger.info(f'Operation status: {status}. Retrying {retry}/5')
                time.sleep(15)
        return "Timeout"

    except Exception as e:
        logger.exception(f'Error occurred while waiting for operation: {operation} to be completed. Error: {e}. '
                         f'Skipping remediation for this instance.')
