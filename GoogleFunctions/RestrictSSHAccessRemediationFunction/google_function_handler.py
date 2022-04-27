import base64
import googleapiclient.discovery
from googleapiclient.errors import HttpError
import json
import logging
import os
import time

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-0-0-3-6-restrict-SSH-access-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Ensure that SSH access is restricted from the internet
    Definition: FirewallRule where Disabled eq False should not have Direction eq "INGRESS" and SourceRanges with [ Value eq 0.0.0.0/0 ] and Allowed with [ Protocol in ("all", "tcp") and Ports with [ FromPort lte 22 and ToPort gte 22 ] ]
    """
    try:
        service = googleapiclient.discovery.build("compute", "v1")

        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))

        for violation in violations.get('violations'):
            project_id = violation.get("account_id")
            firewall_rule_name = violation.get("resource_id").split("/")[-1]
            region = violation.get("region_name")

            logger.info(f"Alert details: Project ID {project_id}, Firewall rule name"
                        f" {firewall_rule_name}, Region {region}")

            status = update_firewall_rule_source_ranges(service, project_id, firewall_rule_name)
            if status:
                logger.info(f"Remediation is successful for the project {project_id},"
                            f" firewall rule {firewall_rule_name} and region {region}")
    except Exception as error:
        raise Exception(f"Error occurred while doing remediation of the use case. Reason: {error}") from error


def wait_for_firewall_operation_complete(service, project_name, operation_name):
    """
    Wait for the firewall operation to complete

    :param service: compute service object
    :param project_name: Name of the project
    :param operation_name: Name of the executed operation to wait for
    """
    try:
        max_retry = 30
        wait_time = 10
        for retry in range(max_retry):
            response = service.globalOperations().wait(project=project_name, operation=operation_name).execute()
            if response.get("status") == "DONE":
                return True
            time.sleep(wait_time)
            logger.info(
                f"Update firewall rule operation {operation_name} is still {response.get('status')}. Retrying {retry}/{max_retry}")
        else:
            logger.info(
                f"Remediation is not completed. Reason: Max retires exceeded while checking operation {operation_name} status")
    except Exception as error:
        raise Exception(f"Remediation might not be completed."
                        f" Error occurred while checking the firewall rule update operation."
                        f" Reason: {error}") from error


def update_firewall_rule_source_ranges(service, project_name, firewall_rule_name):
    """
    Remove "0.0.0.0/0" entry from the firewall rule source ranges

    :param service: compute service object
    :param project_name: Name of the project
    :param firewall_rule_name: firewall rule name
    """
    try:
        firewall_service = service.firewalls()
        source_ranges = firewall_service.get(project=project_name, firewall=firewall_rule_name).execute().get(
            "sourceRanges", [])

        if "0.0.0.0/0" in source_ranges:
            source_ranges.remove("0.0.0.0/0")

            if source_ranges:
                response = firewall_service.patch(project=project_name, firewall=firewall_rule_name,
                                                  body={"name": firewall_rule_name,
                                                        "sourceRanges": source_ranges}).execute()
            else:
                response = firewall_service.delete(project=project_name, firewall=firewall_rule_name).execute()

            logger.debug(f"Firewall rules update/delete response: {response}")
            return wait_for_firewall_operation_complete(service, project_name, response.get("name"))
        else:
            logger.info("No entries found from source ranges for 0.0.0.0/0 from firewall rule")

    except HttpError as http_error:
        if http_error.resp.get('content-type', '').startswith('application/json'):

            error_json = json.loads(http_error.content).get('error').get('errors')[0]
            reason = error_json.get("reason")
            message = error_json.get("message")

            if reason == "resourceNotReady":
                logger.error(f"Error occurred while remediation. Another firewall operation is running for this rule"
                             f" {firewall_rule_name}. Reason: {message}")
            elif reason == "notFound":
                logger.error(f"Error occurred while remediation. Firewall rule {firewall_rule_name} not found."
                             f" Reason: {message}")
            else:
                logger.error(
                    f"Error occurred while updating/removing firewall rule {firewall_rule_name}"
                    f" and project {project_name}."
                    f" Reason: {reason} - {message}")
        else:
            logger.exception(
                f"Error occurred while updating/removing firewall rule {firewall_rule_name} and project {project_name}."
                f" Reason: {http_error}")
    except Exception as error:
        logger.exception(
            f"Error occurred while updating/removing firewall rule {firewall_rule_name} and project {project_name}."
            f" Reason: {error}")

