import base64
import googleapiclient.discovery
import re
import json
import logging
import os

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-0-0-1-4-service-account-admin-privileges-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Identities and credentials: Ensure that ServiceAccount has no Admin privileges.
    Definition: IAMPolicy should not have Members . ServiceEmails with [ Email like "iam\.gserviceaccount\.com$" ]
     and ( Role . id in ("roles/editor", "roles/owner") or Role . id like ".*Admin$" )
    """
    try:
        service = googleapiclient.discovery.build("cloudresourcemanager", "v3")

        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))

        for violation in violations.get('violations'):
            project_id = violation["account_id"]
            role_name = violation["resource_id"].split('roles/')[1]
            role_name = f"roles/{role_name}"
            region = violation["region_name"]
            logger.info(f"Alert details: Project ID {project_id}, Role {role_name}, Region {region}")

            status = remove_service_account_having_admin_privileges(service, project_id, role_name)
            if status:
                logger.info(f"Remediation is successful for the project {project_id}, role {role_name} and"
                            f" region {region}")
    except Exception as error:
        raise Exception(f"Error occurred while doing remediation of the use case. Reason: {error}") from error


def remove_service_account_having_admin_privileges(service, project_id, role_name):
    """
    Removes service account from policy role binding having admin privileges

    :param service: cloud resource manager service object
    :param project_id: ID of the project
    :param role_name: role name from which to remove service account
    """
    try:
        project_id = f"projects/{project_id}"
        policy_binding = service.projects().getIamPolicy(resource=project_id).execute().get("bindings")

        update_policy = False
        for role_binding in policy_binding:
            if role_binding.get("role") == role_name:
                members = role_binding["members"].copy()
                for member in members:
                    if re.fullmatch(r"^serviceAccount:.*iam\.gserviceaccount\.com$", member):
                        role_binding["members"].remove(member)
                        update_policy = True

        if update_policy:
            request_body = {"policy": {"bindings": policy_binding}, "updateMask": "bindings"}
            response = service.projects().setIamPolicy(resource=project_id,
                                                       body=request_body).execute()
            logger.debug(f"Update policy response: {response}")
            return True
        else:
            logger.info(f"No service account found in members of {role_name} binding for project {project_id}")
    except Exception as error:
        logger.exception(f"Error occurred while removing service account from the role {role_name} and project"
                         f" {project_id}. Reason: {error}")
