import base64
import googleapiclient.discovery
import json
import logging
import os
import time
from googleapiclient.errors import HttpError

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-0-0-3-9-vpc-flow-log-enable-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)

GCP_REGION = os.getenv('FUNCTION_REGION', 'us-east-1')


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Communications and control network protection: Ensure VPC Flow logs is enabled for every subnet in VPC
     Network
    Definition: VPC should have every Subnetworks with [ LogEnabled ]
    """
    service = googleapiclient.discovery.build("compute", "v1")

    violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))

    for violation in violations.get('violations'):
        project_id = violation.get("account_id")
        vpc_name = violation.get("resource_id").split("/")[-1]
        region = violation.get("region_name")

        status = enable_flow_logs_for_subnets(service, GCP_REGION, project_id, vpc_name)
        if status:
            logger.info(f"Remediation is successful for the project {project_id},"
                        f" VPC {vpc_name} and region {GCP_REGION}")


def wait_for_vpc_operation_complete(service, region, project_id, operation_name):
    """
    Wait for the firewall operation to complete

    :param service: compute service object
    :param region: Name of the region
    :param project_id: ID of the project
    :param operation_name: Name of the executed operation to wait for
    """
    max_retry = 30
    wait_time = 10
    try:
        for retry in range(max_retry):
            response = service.regionOperations().wait(project=project_id, operation=operation_name,
                                                       region=region).execute()
            if response.get("status") == "DONE":
                return True
            time.sleep(wait_time)
            logger.info(f"Update subnetwork operation {operation_name} is still {response.get('status')}."
                        f" Retrying {retry}/{max_retry}")
        else:
            logger.info(f"Remediation is not completed. Reason: Max retires exceeded while checking operation"
                        f" {operation_name} status")
    except Exception as error:
        raise Exception(f"Remediation might not be completed."
                        f" Error occurred while checking the update subnet operation."
                        f" Reason: {error}") from error


def enable_flow_logs_for_subnets(service, region, project_name, vpc_name):
    """
    Enable flow logging for subnets of given VPC

    :param service: compute service object
    :param region: Name of the region
    :param project_name: Name of the project
    :param vpc_name: VPC Network Name
    """
    try:
        # Validate that VPC network exist in the project
        network_service = service.networks()
        network_service.get(project=project_name, network=vpc_name).execute()

        subnet_service = service.subnetworks()

        # Sub network list API response is giving the URL of the VPC Network instead of name,
        # hence we need to give following URL string to filter subnetworks
        vpc_network_string = f"https://www.googleapis.com/compute/v1/projects/{project_name}/global/networks/{vpc_name}"
        subnets = subnet_service.list(project=project_name, region=region,
                                      filter=f'network="{vpc_network_string}" AND enableFlowLogs=false').execute()
        subnets = subnets.get("items", [])

        if not subnets:
            logger.info(f"VPC flow logging is already enabled for subnetworks present in the region {region}"
                        f" for VPC network {vpc_name}")
            return

        subnet_update_status = []

        for subnet in subnets:
            request_body = {"enableFlowLogs": True, "fingerprint": subnet.get("fingerprint")}
            response = subnet_service.patch(project=project_name, region=region, subnetwork=subnet.get("name"),
                                            body=request_body).execute()
            operation_status = wait_for_vpc_operation_complete(service, region, project_name, response.get("name"))
            logger.info(f"Enabled Flow logging for subnet {subnet.get('name')}, VPC Network"
                        f" {vpc_name} and region {region}")
            subnet_update_status.append(operation_status)

        if subnet_update_status and all(subnet_update_status):
            return True
        else:
            logger.error("Error occurred while enabling flow logging in subnets."
                         " Failed to enable flow logging in some of subnets")

    except HttpError as http_error:
        if http_error.resp.get('content-type', '').startswith('application/json'):

            error_json = json.loads(http_error.content).get('error').get('errors')[0]
            reason = error_json.get("reason")
            message = error_json.get("message")

            if reason == "resourceNotReady":
                logger.error(f"Error occurred while remediation. Another VPC network operation is running"
                             f" for {vpc_name}. Reason: {message}")
            elif reason == "notFound":
                logger.error(f"Error occurred while remediation. VPC network {vpc_name} not found. Reason: {message}")
            else:
                logger.error(f"Error occurred while enabling flow logs for the VPC network"
                             f" {vpc_name} and project {project_name}. Reason: {reason} - {message}")

        else:
            logger.exception(f"Error occurred while enabling flow logs for the VPC network"
                             f" {vpc_name} and project {project_name}. Reason: {http_error}")
    except Exception as error:
        logger.exception(f"Error occurred while enabling flow logs for the VPC network"
                         f" {vpc_name} and project {project_name}. Reason: {error}")
