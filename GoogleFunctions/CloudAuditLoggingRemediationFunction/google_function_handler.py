import base64
import googleapiclient.discovery
import json
import logging
import os

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-0-0-2-1-cloud-audit-logging-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Audit/log records: Ensure that Cloud Audit Logging is configured properly across all services and all
     users from a project
    Definition: GCP should have atleast one AuditConfigs with [ Service eq "allServices" and AuditLogConfigs with
     [ LogType eq "DATA_READ" ] and AuditLogConfigs with [ LogType eq "DATA_WRITE" ] and AuditLogConfigs with
      [ LogType eq "ADMIN_READ" ] ] and every AuditConfigs with [ HasExemptedMembers eq False ]
    """
    try:
        service = googleapiclient.discovery.build("cloudresourcemanager", "v3")

        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))

        for violation in violations.get('violations'):

            project_id = violation.get("account_id")
            project_id_to_set_audit_logging = violation.get("resource_id")
            region = violation.get("region_name")

            logger.info(f"Alert details: Project ID {project_id}, Project ID to configure Audit logging"
                        f" {project_id_to_set_audit_logging}, Region {region}")

            status = check_and_configure_all_services_audit_logging(service, project_id_to_set_audit_logging)
            if status:
                logger.info(f"Remediation is successful for the project {project_id},"
                            f" Project ID to configure Audit logging {project_id_to_set_audit_logging} and"
                            f" region {region}")
    except Exception as error:
        raise Exception(f"Error occurred while doing remediation of the use case. Reason: {error}") from error


def check_and_configure_all_services_audit_logging(service, project_id):
    """
    Check and configure audit logging for the project

    :param service: cloud resource manager service object
    :param project_id: ID of the project
    """
    try:
        audit_configs = service.projects().getIamPolicy(resource=project_id).execute().get("auditConfigs", [])

        all_services_audit_log_configs = [
          {
            "logType": "DATA_READ"
          },
          {
            "logType": "DATA_WRITE"
          },
          {
            "logType": "ADMIN_READ"
          }
        ]
        is_all_services_audit_config_present = False
        update_policy = False

        for audit_config in audit_configs:
            if audit_config["service"] == "allServices":
                audit_config["auditLogConfigs"] = all_services_audit_log_configs
                is_all_services_audit_config_present = True
                update_policy = True

            for audit_log_config in audit_config.get("auditLogConfigs", []):
                if audit_log_config.get("exemptedMembers"):
                    del audit_log_config["exemptedMembers"]
                    update_policy = True

        # Adding allservices in audit configs
        if not is_all_services_audit_config_present:
            audit_configs.append({
              "service": "allServices",
              "auditLogConfigs": all_services_audit_log_configs
            })
            update_policy = True

        if update_policy:
            policy_body = {"policy": {"auditConfigs": audit_configs}, "updateMask": "auditConfigs"}
            response = service.projects().setIamPolicy(resource=project_id,
                                                       body=policy_body).execute()
            logger.debug(f"Update policy response: {response}")
            return True
        else:
            logger.info("Audit logging is already properly configured.")

    except Exception as error:
        logger.exception(f"Error occurred while configuring audit logging from the project {project_id}."
                         f" Reason: {error}")
