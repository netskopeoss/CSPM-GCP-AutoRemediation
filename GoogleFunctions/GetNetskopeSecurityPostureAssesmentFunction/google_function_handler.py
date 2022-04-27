import json
import requests
import os
import logging
import base64
from google.cloud import pubsub_v1
from googleapiclient import discovery

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'DEBUG')
logger = logging.getLogger("get-alert-function")
level_name = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level_name)

TENANT_FQDN_NAME = "NetskopeTenantFQDN"
API_TOKEN_NAME = "NetskopeAPIToken"

PROJECT_ID = os.getenv("GCP_PROJECT")

CHUNK_SIZE = 100
GCP_REGION = os.getenv('FUNCTION_REGION', 'us-east-1')
GCP_REGIONS = {
    "asia-east1": ["ASIA", "Changhua County, Taiwan"],
    "asia-east2": ["ASIA", "Hong Kong"],
    "asia-northeast1": ["ASIA", "ASIA1", "Tokyo, Japan"],
    "asia-northeast2": ["ASIA", "Osaka, Japan, APAC", "ASIA1"],
    "asia-northeast3": ["ASIA", "Seoul, South Korea, APAC"],
    "asia-south1": ["ASIA", "Mumbai, India"],
    "asia-south2": ["ASIA", "Delhi, India, APAC"],
    "asia-southeast1": ["ASIA", "Jurong West, Singapore"],
    "asia-southeast2": ["ASIA", "Jakarta, Indonesia, APAC"],
    "australia-southeast1": "Sydney, Australia",
    "australia-southeast2": "Melbourne, Australia, APAC",
    "europe-central2": ["EU", "Warsaw, Poland, Europe"],
    "europe-north1": ["EU", "EUR4", "Hamina, Finland"],
    "europe-west1": ["EU", "St. Ghislain, Belgium"],
    "europe-west2": ["EU", "London, England, UK"],
    "europe-west3": ["EU", "Frankfurt, Germany"],
    "europe-west4": ["EU", "Eemshaven, Netherlands", "EUR4"],
    "europe-west6": ["EU", "Zurich, Switzerland, Europe"],
    "northamerica-northeast1": "Montreal, Quebec, Canada",
    "northamerica-northeast2": "NORTHAMERICA-NORTHEAST2",
    "southamerica-east1": "Sao Paulo, Brazil",
    "southamerica-west1": "SOUTHAMERICA-WEST1",
    "us-central1": ["NAM4", "US", "Council Bluffs, Iowa, USA"],
    "us-east1": ["US", "Moncks Corner, South Carolina, USA", "NAM4"],
    "us-east4": ["US", "Ashburn, Northern Virginia, USA"],
    "us-west1": ["US", "The Dalles, Oregon, USA"],
    "us-west2": ["US", "Los Angeles, California, USA"],
    "us-west3": ["US", "Salt Lake City, Utah, North America"],
    "us-west4": ["US", "Las Vegas, Nevada, North America"]
}


def get_secret_value(secret_name):
    """
    Retrieve secret from the secret manager
    :param secret_name: Name of the secret parameter
    """
    try:
        service = discovery.build("secretmanager", "v1")
        versions = service.projects().secrets().versions()

        response = versions.access(name=f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest").execute()
        return base64.b64decode(response.get("payload", {}).get("data", "")).decode()

    except Exception as error:
        raise Exception(f"Error occurred while retrieving Netskope secret {secret_name} from secret manager."
                        f" Reason: {error}") from error


def google_cloud_function_handler(event, context):
    """
    Retrieve the violations from Netskope CSPM and publish the violations in the pub/sub
    """
    try:
        token = get_secret_value(API_TOKEN_NAME)
        tenant_fqdn = get_secret_value(TENANT_FQDN_NAME)

        event_dict = event['attributes']
        rule_name = event_dict['rule_name']
        rule_short_name = event_dict['rule_short_name']

        violations_to_publish = []
        page_number = 0
        alert_count = 0

        violations = get_rule_violations(rule_name, token, tenant_fqdn, str(CHUNK_SIZE), str(page_number * CHUNK_SIZE))

        # Iterate through violations and add them in list if matches the current region
        while len(violations):
            for violation in violations:
                violation_info = f"account {violation['account_id']} account name"\
                                 f" {violation['account_name']} resource_id {violation['resource_id']} resource_name"\
                                 f" {violation['resource_name']} rule_name {violation['rule_name']}"

                logger.debug(f"Got violation: {violation_info}")

                region = GCP_REGIONS.get(GCP_REGION)
                check_region_list = type(region) is list and violation["region_name"] in region
                check_region_str = type(region) is str and violation["region_name"] == region

                if check_region_list or check_region_str or violation["region_name"] == "global"\
                        or violation["region_name"] == "":
                    logger.info(f"Got violation from this region for the {violation_info}")
                    violations_to_publish.append({"account_id": violation["account_id"],
                                                  "resource_id": violation["resource_id"],
                                                  "region_name": violation["region_name"]})
                    alert_count += 1
                    logger.debug("Violation is from this region")
                else:
                    logger.debug("Violation is from another region")

            page_number += 1

            violations = get_rule_violations(rule_name, token, tenant_fqdn,
                                             str(CHUNK_SIZE), str(page_number * CHUNK_SIZE))

        logger.info(f"Got {alert_count} total violations for the rule {rule_name}")

        if alert_count:
            # Publish messages on pubsub
            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(PROJECT_ID, rule_short_name)
            violations_json = json.dumps({"violations": violations_to_publish}).encode('utf-8')
            response = publisher.publish(topic_path, data=violations_json)
            response.result()

    except Exception as error:
        raise Exception(f"Error occurred while getting Netskope CSPM results. Reason: {error}") from error


def get_rule_violations(rule_name, token, tenant_fqdn, limit, skip):
    """
    Retrieve the alerts from Netskope for the given parameters

    :param rule_name: Name of the rule to retrieve the alerts for
    :param token: Token for Authentication
    :param tenant_fqdn: Tenant host name
    :param limit: No of alerts to retrieve
    :param skip: No of alerts to skip
    """
    try:
        get_url = f"https://{tenant_fqdn}/api/v1/security_assessment"
        payload = {'token': token, 'cloud_provider': 'googlecloud', 'status': 'Failed', 'muted': 'No',
                   'rule_name': rule_name,
                   'limit': limit, 'skip': skip}

        logger.info(f"Calling Netskope API for {rule_name}")

        response = requests.get(get_url, params=payload)
        response.raise_for_status()

        return response.json()["data"]
    except Exception as error:
        raise Exception(f"Error occurred while calling Netskope API. Reason: {error}") from error
