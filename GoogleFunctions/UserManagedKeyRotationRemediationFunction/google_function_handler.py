import base64
import googleapiclient.discovery
import json
import logging
import os
from googleapiclient.errors import HttpError
from datetime import datetime

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-0-0-1-6-user-managed-key-rotation-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)

INACTIVE_KEYS_AFTER_DAYS = 90


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Identities and credentials: Ensure user-managed/external keys for service accounts are
     rotated every 90 days or less
    Definition: ServiceAccount should have every Keys with [ Validity . AfterTime isLaterThan ( -90, "days" ) ]
    """
    try:
        service = googleapiclient.discovery.build("iam", "v1")

        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))

        for violation in violations.get('violations'):

            project_id = violation.get("account_id")
            service_account = violation.get("resource_id")
            region = violation.get("region_name")

            logger.info(f"Alert details: Project ID {project_id}, Service account"
                        f" {service_account}, Region {region}")

            status = check_and_inactive_user_managed_keys(service, service_account)
            if status:
                logger.info(f"Remediation is successful for the project {project_id},"
                            f" Service account {service_account} and"
                            f" region {region}")
    except Exception as error:
        raise Exception(f"Error occurred while doing remediation of the use case. Reason: {error}") from error


def check_and_inactive_user_managed_keys(service, service_account):
    """
    Inactive user managed service account keys of user that are older than 90 days

    :param service: IAM container service object
    :param service_account: Service account to check the keys of
    """
    try:
        keys = service.projects().serviceAccounts().keys().list(name=service_account,
                                                                keyTypes='USER_MANAGED'
                                                                ).execute().get("keys", [])
        is_key_disabled = False
        for key in keys:

            current_time = datetime.utcnow()
            key_after_time = datetime.strptime(key.get("validAfterTime", ""), "%Y-%m-%dT%H:%M:%SZ")
            time_diff_days = (current_time - key_after_time).days

            if not key.get("disabled") and time_diff_days >= INACTIVE_KEYS_AFTER_DAYS:
                service.projects().serviceAccounts().keys().disable(name=key.get("name")).execute()
                logger.info(f'User managed key {key.get("name")} disabled for the service account {service_account}')
                is_key_disabled = True

        if not is_key_disabled:
            logger.info(f'No active user managed keys found that were created before 90 days for service account'
                        f' {service_account}.')

        return is_key_disabled
    except HttpError as http_error:
        if http_error.resp.get('content-type', '').startswith('application/json'):

            error_json = json.loads(http_error.content).get('error')
            status = error_json.get("status")
            message = error_json.get("message")

            if status == "NOT_FOUND":
                logger.error(f"Error occurred while remediation. Service account or service account "
                             f"key not found for service account {service_account}"
                             f" Reason: {message}")
            else:
                logger.error(f"Error occurred while disabling keys for the"
                             f" service account {service_account}. Reason: {status} - {message}")

        else:
            logger.exception(f"Error occurred while disabling keys for the"
                             f" service account {service_account}. Reason: {http_error}")
    except Exception as error:
        logger.exception(f"Error occurred while disabling keys for the"
                         f" service account {service_account}. Reason: {error}")
