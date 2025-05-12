
import logging
import random
import string
import time
import json
import pytest
import boto3

# from datetime import datetime, timedelta
# from fortiqa.libs.helper.date_helper import calculate_time_range
# from fortiqa.libs.lw.apiv1.api_client.alerts.alerts import Alerts
from fortiqa.tests import settings
# from botocore.exceptions import ClientError
# from playwright.sync_api import sync_playwright
# from conftest import SLEEP_TIMEOUT, QUERY_TIMEOUT, FILTER_TIME_RANGE

from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)

def modify_policy(api_v1_client, action, policy_list, wait_time): 
    payload = {}
    
    if action == "disabled":
        payload.update({"enabled": False})
    elif action == "enabled":
        payload.update({"enabled": True})

    lacework_account = settings.app.customer['account_name']

    for policy_id in policy_list:
        url = f"https://{lacework_account}.lacework.net/api/v1/Policies/{policy_id}"
        response = api_v1_client.patch(url, payload)
        logger.info(f"{policy_id} is {action} with status code: {response}")

    logger.info("Waiting for policy change to take effect ...")
    time.sleep(wait_time)    

def modify_policy_severity(api_v1_client, action, policy_list, wait_time): 
    payload = {}
    
    if action == "critical":
        payload.update({"severity": "critical"})
    elif action == "high":
        payload.update({"severity": "high"})
    elif action == "medium":
        payload.update({"severity": "medium"})
    elif action == "low":
        payload.update({"severity": "low"})
    elif action == "info":
        payload.update({"severity": "info"})

    lacework_account = settings.app.customer['account_name']

    for policy_id in policy_list:
        url = f"https://{lacework_account}.lacework.net/api/v1/Policies/{policy_id}"
        response = api_v1_client.patch(url, payload)
        logger.info(f"{policy_id} is {action} with status code: {response}")

    logger.info("Waiting for policy change to take effect ...")
    time.sleep(wait_time)    

def filter_payload_helper(alert_name, start_time, end_time): 
    payload = {
        "Filters": {
            "AlertMetadataFilters.NAME": [
                {
                    "filterGroup": "Includes",
                    "value": alert_name
                }
             ],
            "AlertMetadataFilters.STATUS":[
                {
                    "filterGroup":"Includes",
                    "value":"Open"
                }
            ]
        },
        "OrderBy": {
            "field": "START_TIME",
            "order": "Desc"
        },
        "ParamInfo": {
            "StartTimeRange": start_time,
            "EndTimeRange": end_time
        }
    }

    return payload

def alert_assert(resp, alertName, actor, model, severity): 
    assert resp.json()['data'][0]['alertName'] == alertName
    assert resp.json()['data'][0]['actor'] == actor
    assert resp.json()['data'][0]['model'] == model
    assert resp.json()['data'][0]['severity'] == severity
    logger.info(f"***** alert: {alertName}* is generated successfully.")



