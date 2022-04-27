import time
import logging
import os
import json
import base64
from googleapiclient import discovery

LOG_LEVEL = os.getenv('LOGLEVEL', 'INFO')
logger = logging.getLogger("CIS-1-0-0-4-2-ProjectWideSSHKeyRemediationFunction")
logger.setLevel(logging.getLevelName(LOG_LEVEL))
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)


def google_cloud_function_handler(event, context):
    """
    Google Cloud function for the use case:
        Rule Name: Remote access: Ensure "Block Project-wide SSH keys" enabled for VM instances
        Definition: Instance should have Metadata items with [ Key eq "block-project-ssh-keys" and Value like "True" ]
    """
    try:
        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))
        for violation in violations.get('violations'):
            project_id = violation["account_id"]
            instance = violation["resource_id"].split('instances/')[1]
            zone = violation["resource_id"].split("zones/")[1].split("/")[0]

            logger.info(f'Got event with Project ID: {project_id}, VM Instance: {instance} '
                        f'and Zone: {zone}')
            enable_block_project_wide_ssh_keys_for_vm_instance(instance, project_id, zone)

    except Exception as error:
        raise Exception(f'Error occurred while doing remediation of the use case. Reason: {error}') from error


def enable_block_project_wide_ssh_keys_for_vm_instance(instance, project_id, zone):
    """
    This function enables block project-wide ssh keys for VM instance
    :param instance: Name of Compute Engine VM Instance
    :param project_id: Id of the project
    :param zone: Zone of Compute Engine VM Instance
    """
    try:
        service = discovery.build('compute', 'v1')

        # get metadata of a VM instance.
        instance_metadata = service.instances().get(project=project_id, instance=instance, zone=zone).execute()
        logger.debug(f'response from get call : {instance_metadata}')
        is_ssh_key_present = True
        if "items" in instance_metadata['metadata']:
            metadata_items = instance_metadata['metadata']['items']
            for item in metadata_items:
                if item['key'] == 'block-project-ssh-keys' and (item['value'] == 'True' or item['value'] == 'true'):
                    logger.info(f'Remediation was already completed for VM Instance: {instance} of Project: '
                                f'{project_id} and Zone: {zone}')
                    return 0
                elif item['key'] == 'block-project-ssh-keys' and (item['value'] == 'False' or item['value'] == 'false'):
                    # Update parameter 'block-project-ssh-keys' value to True
                    item['value'] = True
                    is_ssh_key_present = True
                    break
                else:
                    is_ssh_key_present = False

            if not is_ssh_key_present:
                new_item = {"key": "block-project-ssh-keys", "value": True}
                # Append new item to metadata items
                instance_metadata['metadata']['items'].append(new_item)
        else:
            # Add items key in instance metadata
            instance_metadata['metadata'].update(items=[{"key": "block-project-ssh-keys", "value": True}])

        response = service.instances().setMetadata(project=project_id, zone=zone, instance=instance,
                                                   body=instance_metadata['metadata']).execute()
        logger.debug(f'response from setMetadata call : {response}')
        operation = response['name']
        # wait for operation to complete
        status = wait_for_operation_to_complete(service, project_id, zone, operation)
        if status == "DONE":
            logger.info(f'Successfully completed remediation for VM Instance: {instance} of '
                        f'Project: {project_id} and Zone: {zone}')
        elif status == "Timeout":
            logger.warning(f'Timed out while waiting for operation: {operation} to be completed. '
                           f'Skipping remediation for this VM Instance: {instance} of Project: {project_id} '
                           f'and Zone: {zone}')

    except Exception as error:
        logger.exception(f'Error occurred while doing remediation for VM Instance: {instance}. '
                         f'Skipping remediation for this VM instance. Reason: {error}')


def wait_for_operation_to_complete(service, project, zone, operation):
    try:
        logger.info(f'Waiting for operation to finish...')
        for retry in range(1, 6):
            result = service.zoneOperations().get(project=project, zone=zone,
                                                  operation=operation).execute()
            logger.debug(f'response from get operation call: {result}')
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

    except Exception as error:
        logger.exception(f'Error occurred while waiting for operation: {operation} to be completed. Error: {error}. '
                         f'Skipping remediation for this VM Instance.')
    