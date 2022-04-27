import base64
import googleapiclient.discovery
import json
import logging
import os

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-2-0-1-6-service-account-role-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator
     roles at project level
    Definition: IAMPolicy where Name eq "iam.serviceAccountUser" or Name eq "iam.serviceAccountTokenCreator"
     should have Members . UserEmails len() eq 0
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

            if role_name in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"):
                status = remove_iam_users_having_service_account_user_or_token_role(service, project_id, role_name)
                if status:
                    logger.info(f"Remediation is successful for the project {project_id}, role {role_name} and"
                                f" region {region}")
            else:
                logger.info("Remediation will only work with role name "
                            "iam.serviceAccountTokenCreator or iam.serviceAccountUser")

    except Exception as error:
        raise Exception(f"Error occurred while doing remediation of the use case. Reason: {error}") from error


def remove_iam_users_having_service_account_user_or_token_role(service, project_id, role_name):
    """
    Removes IAM users from service account user or service account token creator role
    from policy role binding

    :param service: cloud resource manager service object
    :param project_id: ID of the project
    :param role_name: role name from which to remove service account
    """
    try:
        project_id = f"projects/{project_id}"
        policy_binding = service.projects().getIamPolicy(resource=project_id).execute().get("bindings", [])

        if role_name in str(policy_binding):
            for role_binding in policy_binding:
                if role_name == role_binding.get("role"):
                    members = [member for member in role_binding.get("members", []) if
                               not member.startswith('user:')]

                    if len(members) == len(role_binding.get("members", [])):
                        logger.info(f"No users found in IAM policy binding for role {role_name} and"
                                    f" project {project_id}")
                        return

                    if members:
                        role_binding["members"] = members
                    else:
                        policy_binding.remove(role_binding)

                    request_body = {"policy": {"bindings": policy_binding}, "updateMask": "bindings"}
                    response = service.projects().setIamPolicy(resource=project_id,
                                                               body=request_body).execute()
                    logger.debug(f"Update policy response: {response}")
                    return True
        else:
            logger.info(f"No policy binding found for role {role_name} and project {project_id}")
    except Exception as error:
        logger.exception(f"Error occurred while removing role binding for role {role_name} and project"
                         f" {project_id}. Reason: {error}")
