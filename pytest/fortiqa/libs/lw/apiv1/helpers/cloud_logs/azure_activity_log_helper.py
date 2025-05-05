import json
import logging
import time

from copy import deepcopy
from datetime import datetime
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.payloads import AcitivityLogFilters, AlertMetadataFilter
from fortiqa.libs.lw.apiv1.helpers.cloud_logs.cloud_logs_helpers import CloudLogsHelper
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations
from typing import Any

logger = logging.getLogger(__name__)


class ActivityLogHelper(CloudLogsHelper):
    def __init__(self, user_api, fix_timestamp: datetime = datetime.now()):
        super().__init__(user_api=user_api, fix_timestamp=fix_timestamp)

    def list_all_azure_subscription(self):
        """Helper function to list all Azure Subscriptions"""
        logger.info("list_all_azure_subscription()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureSubscriptionList", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All Azure Subscriptions: {json.dumps(query_card_response.json(), indent=2)}")
        # Response data:
        # {
        #     "ok": true,
        #     "data": [
        #         {
        #             "TENANT_ID": "xx",
        #             "TENANT_NAME": "xx",
        #             "SUBSCRIPTION_ID": "xx",
        #             "SUBSCRIPTION_NAME": "[LWTEST] se-demo-beta"
        #         }
        #     ]
        # }
        return query_card_response.json()['data']

    def fetch_subscription_name_by_id(self, azure_subscription_id: str) -> str:
        """
        Helper function to fetch Azure Subscription Name by Subscription Id

        :param azure_subscription_id: azure Subscription Name
        :return: Subscription Name
        """
        logger.info(f"fetch_subscription_name_by_id({azure_subscription_id=})")
        all_subscriptions = self.list_all_azure_subscription()
        for subscription in all_subscriptions:
            if subscription['SUBSCRIPTION_ID'] == azure_subscription_id:
                return subscription['SUBSCRIPTION_NAME']
        raise Exception(f"Not found any subscription has ID: {azure_subscription_id}")

    def get_activity_log_event_data_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Events graph of a specific azure Subscription Name inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of event cound data
        """
        logger.info(f"get_activity_log_event_data_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_RawEvent", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Events data: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_user_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique User graph of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique usernames counted by interval
        """
        logger.info(f"get_activity_log_unique_user_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_User", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique User: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_subscriptions_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique Subscriptions graph of a specific azure Project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique Subscriptions counted by interval
        """
        logger.info(f"get_activity_log_unique_subscriptions_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_Subscription", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Projects: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_resource_types_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique Resource Types graph of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique Resource Types counted by interval
        """
        logger.info(f"get_activity_log_unique_resource_types_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_ResourceType", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Methods: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_alerts_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique Alerts graph of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique alerts counted by interval
        """
        logger.info(f"get_activity_log_unique_alerts_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_Alert", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Alerts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_operations_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique operations graph of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique operations counted by interval
        """
        logger.info(f"get_activity_log_unique_operations_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_Operation", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Resource Types: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_regions_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique Regions graph of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique Regions counted by interval
        """
        logger.info(f"get_activity_log_unique_regions_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_CallerRegion", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Regions: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_unique_errors_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get data that generated the Unique Errors graph of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of unique Errors counted by interval
        """
        logger.info(f"get_activity_log_unique_errors_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogTS_Error", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Errors: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_alert_box_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get active High-Priority Alerts of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of Active High-Priority Alerts
        """
        logger.info(f"get_activity_log_alert_box_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ],
            AlertMetadataFilter.SEVERITY: [
                {
                    "filterGroup": "Includes",
                    "value": "Critical"
                },
                {
                    "filterGroup": "Includes",
                    "value": "High"
                },
                {
                    "filterGroup": "Includes",
                    "value": "Medium"
                }
            ],
            AlertMetadataFilter.STATUS: [
                {
                    "filterGroup": "Includes",
                    "value": "Open"
                },
                {
                    "filterGroup": "Includes",
                    "value": "InProgress"
                }
            ],
            AlertMetadataFilter.SOURCE: [
                {
                    "filterGroup": "Includes",
                    "value": "azure"
                }
            ],
            AlertMetadataFilter.SUB_CATEGORY: [
                {
                    "filterGroup": "Includes",
                    "value": "Cloud Activity"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card113_AlertInbox", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Active High-Priority Alerts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_logs_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get Activity log logs collected of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of User events
        """
        logger.info(f"get_activity_log_logs_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogDetails", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Activity logs: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_user_details_by_Subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get Activity log user details collected of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of User events
        """
        logger.info(f"get_activity_log_user_details({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogDetailsByIdentity", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"User details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_activity_log_api_error_events_by_azure_subscription_name(self, azure_subscription_name: str) -> list:
        """
        Helper function to get API Error Events collected of a specific azure project inside Activity log page

        :param azure_subscription_name: azure Subscription Name
        :return: List of API Error Events
        """
        logger.info(f"get_activity_log_api_error_events_by_azure_subscription_name({azure_subscription_name=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AcitivityLogFilters.SUBSCRIPTION_NAME: [
                {
                    "value": azure_subscription_name,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AzureActivityLogErrorInfo", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"API Error Events: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def wait_until_specific_event_resource_appear(self, azure_subscription_name: str, resource_name: str, operation_name: str, timeout: int = 3600) -> bool:
        """
        Helper function to wait until a specfic event to appear after new ActivityLogs logs pushed to Lacework Database by checking operation_name and resource_id

        :param azure_subscription_name: azure Subscription Name
        :param resource_name: Resource Name to check
        :param operation_name: Name of the expected operation
        :param timeout: Maximum time to wait until new logs to appear
        """
        logger.info(f"wait_until_specific_event_resource_appear({azure_subscription_name}:{resource_name}, {operation_name=})")
        start_time = time.monotonic()
        found = False
        timed_out = False
        while not found and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            activitylog_log = self.get_activity_log_logs_by_azure_subscription_name(azure_subscription_name)
            for log in activitylog_log:
                if log['OPERATION_NAME'] == operation_name and resource_name in log['RESOURCE_ID'].lower():
                    found = True
            if not found:
                time.sleep(60)
        if found:
            logger.info(f"Event {operation_name} with {resource_name=} appears inside ActivityLog logs after {time_passed} seconds")
            return found
        raise TimeoutError(f"Event {operation_name} with {resource_name=} did not appear inside Lacework after {timeout} seconds, last collected logs: {json.dumps(activitylog_log, indent=2)}")

    def wait_until_specific_event_resource_appear_before_timestamp(self, azure_subscription_name: str, resource_name: str, operation_name: str, wait_until: int) -> bool:
        """
        Helper function to wait until a specfic event to appear after new ActivityLogs logs pushed to Lacework Database by checking operation_name and resource_id

        :param azure_subscription_name: azure Subscription Name
        :param resource_name: Resource Name to check
        :param operation_name: Name of the expected operation
        :param wait_until: Unix time until we wait for event to be found.
        """
        logger.info(f"wait_until_specific_event_resource_appear_before_timestamp({azure_subscription_name}:{resource_name}, {operation_name=})")
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(300)
            first_try = False
            activitylog_log = self.get_activity_log_logs_by_azure_subscription_name(azure_subscription_name)
            for log in activitylog_log:
                if log['OPERATION_NAME'] == operation_name and resource_name in log['RESOURCE_ID'].lower():
                    found = True
        if found:
            logger.info(f"Event {operation_name} with {resource_name=} appears inside ActivityLog logs before given timestamp")
            return found
        raise TimeoutError(f"Event {operation_name} with {resource_name=} did not appear inside Lacework after given timestamp, last collected logs: {json.dumps(activitylog_log, indent=2)}")

    def wait_until_azure_activity_log_account_added_after_timestamp_with_tenant_id(self, timestamp: datetime, tenant_id: str, timeout: int = 600) -> Any | None:
        """
        Helper function to wait until a azure ActivityLog integration with a specific tenant_id created with and added after a specific timestamp

        :param tenant_id: Azure Tenant ID
        :param timestamp: A fixed timestamp
        :param timeout: Maximum time to wait

        :return: Account found
        """
        logger.info(f"wait_until_azure_activity_log_account_added_after_timestamp_with_tenant_id({tenant_id}=)")
        start_time = time.monotonic()
        found = False
        timed_out = False
        integration_client = Integrations(self.user_api)
        account_found = None
        while not found and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            all_accounts = integration_client.get_cloud_accounts().json()['data']
            for cloud_account in all_accounts:
                if cloud_account['TYPE'] == "AZURE_AL_SEQ" and cloud_account['CREATED_OR_UPDATED_TIME'] > timestamp:
                    intg_guid = cloud_account['INTG_GUID']
                    current_account_info = integration_client.get_cloud_account_by_intg_guid(intg_guid).json()['data'][0]
                    if current_account_info['DATA']['TENANT_ID'] == tenant_id:
                        found = True
                        account_found = current_account_info
                        break
            if not found:
                time.sleep(60)
        if found:
            logger.info(f"Azure ActivityLog integration with {tenant_id=} appears after {time_passed} seconds, {account_found=}")
            return account_found
        raise TimeoutError(f"Azure ActivityLog integration with {tenant_id=} does not appear after {time_passed} seconds")
