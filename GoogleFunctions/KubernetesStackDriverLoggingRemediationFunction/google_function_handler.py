import base64
import googleapiclient.discovery
import json
import logging
import os
import time
from googleapiclient.errors import HttpError

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("CIS-1-0-0-7-1-kubernetes-stack-driver-logging-remediation-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)


def google_cloud_function_handler(event, context):
    """
    Google Cloud function handler for the use case:
    Rule Name: Audit/log records: Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters
    Definition: KubernetesCluster should have LoggingService in ( "logging.googleapis.com",
     "logging.googleapis.com/kubernetes")
    """
    try:
        service = googleapiclient.discovery.build("container", "v1")

        violations = json.loads(base64.b64decode(event['data']).decode('utf-8'))

        for violation in violations.get('violations'):

            project_id = violation.get("account_id")
            kubernetes_cluster_name = violation.get("resource_id")
            region = violation.get("region_name")

            logger.info(f"Alert details: Project ID {project_id}, Kubernetes cluster Name"
                        f" {kubernetes_cluster_name}, Region {region}")

            status = set_logging_in_kubernetes_cluster(service, kubernetes_cluster_name)
            if status:
                logger.info(f"Remediation is successful for the project {project_id},"
                            f"  Kubernetes cluster name {kubernetes_cluster_name} and"
                            f" region {region}")
    except Exception as error:
        raise Exception(f"Error occurred while doing remediation of the use case. Reason: {error}") from error


def wait_for_set_logging_operation_complete(service, kubernetes_cluster_name, operation_name):
    """
    Wait for the set kubernetes logging operation to complete

    :param service: kubernetes container service object
    :param kubernetes_cluster_name: Name of the kubernetes cluster
    :param operation_name: Name of the executed operation to wait for
    """
    try:
        max_retry = 60
        wait_time = 10
        name = f"{kubernetes_cluster_name.split('clusters')[0]}operations/{operation_name}"
        for retry in range(max_retry):
            response = service.projects().locations().operations().get(name=name).execute()
            if response.get("status") == "DONE":
                return True
            time.sleep(wait_time)
            logger.info(
                f"Set kubernetes cluster logging"
                f" operation {operation_name} is still {response.get('status')}. Retrying {retry}/{max_retry}")
        else:
            logger.info(
                f"Remediation is not completed. Reason: Max retires exceeded while checking operation {operation_name}"
                f" status")
    except Exception as error:
        raise Exception(f"Remediation might not be completed."
                        f" Error occurred while checking the kubernetes cluster set logging operation."
                        f" Reason: {error}") from error


def set_logging_in_kubernetes_cluster(service, kubernetes_cluster_name):
    """
    Set logging in kubernetes cluster

    :param service: kubernetes container service object
    :param kubernetes_cluster_name: Name of the kubernetes cluster
    """
    try:
        logging_service = service.projects().locations().clusters().get(name=kubernetes_cluster_name
                                                                        ).execute().get("loggingService", "none")
        if logging_service and logging_service == "none":
            body = {"loggingService": "logging.googleapis.com/kubernetes"}
            response = service.projects().locations().clusters().setLogging(name=kubernetes_cluster_name,
                                                                            body=body).execute()
            logger.debug(f"Set kubernetes cluster logging response: {response}")
            return wait_for_set_logging_operation_complete(service, kubernetes_cluster_name, response.get("name"))
        else:
            logger.info(f"Kubernetes cluster logging is already set with service {logging_service}.")

    except HttpError as http_error:
        if http_error.resp.get('content-type', '').startswith('application/json'):

            error_json = json.loads(http_error.content).get('error')
            status = error_json.get("status")
            message = error_json.get("message")

            if status == "NOT_FOUND":
                logger.error(f"Error occurred while remediation. kubernetes cluster {kubernetes_cluster_name}"
                             f" not found. Reason: {message}")
            else:
                logger.error(f"Error occurred while setting kubernetes cluster logging from the"
                             f" kubernetes cluster {kubernetes_cluster_name}."
                             f" Reason: {status} - {message}")

        else:
            logger.exception(f"Error occurred while setting kubernetes cluster logging from the"
                             f" kubernetes cluster {kubernetes_cluster_name}. Reason: {http_error}")
    except Exception as error:
        logger.exception(f"Error occurred while setting kubernetes cluster logging from the"
                         f" kubernetes cluster {kubernetes_cluster_name}. Reason: {error}")
