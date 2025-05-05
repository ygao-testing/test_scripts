import json
import logging
import time

from copy import deepcopy
from datetime import datetime
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.payloads import AuditLogFilters, AlertMetadataFilter
from fortiqa.libs.lw.apiv1.helpers.cloud_logs.cloud_logs_helpers import CloudLogsHelper
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations
from typing import Any

logger = logging.getLogger(__name__)


class AuditLogHelper(CloudLogsHelper):
    def __init__(self, user_api, fix_timestamp: datetime = datetime.now()):
        super().__init__(user_api=user_api, fix_timestamp=fix_timestamp)

    def list_all_organizations(self):
        """Helper function to list all GCP Organizations"""
        logger.info("list_all_organizations()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogProjectList", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All GCP Organizations: {json.dumps(query_card_response.json(), indent=2)}")
        # Response data:
        # {
        #     "ok": true,
        #     "data": [
        #         {
        #             "ORGANIZATION_ID": null,
        #             "ORGANIZATION_NAME": null,
        #             "PROJECT_ID": "lacework-demo-beta",
        #             "PROJECT_NAME": "lacework-demo-beta"
        #         }
        #     ]
        # }
        return query_card_response.json()['data']

    def get_audit_log_event_data_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Events graph of a specific GCP Project ID inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of event cound data
        """
        logger.info(f"get_audit_log_event_data_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_RawEvent", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Events data: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_user_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique User graph of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project ID
        :return: List of unique usernames counted by interval
        """
        logger.info(f"get_audit_log_unique_user_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_User", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique User: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_projects_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique Projects graph of a specific gcp Project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of unique Projects counted by interval
        """
        logger.info(f"get_audit_log_unique_projects_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_Project", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Projects: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_methods_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique Methods graph of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of unique Methods counted by interval
        """
        logger.info(f"get_audit_log_unique_methods_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_Method", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Methods: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_alerts_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique Alerts graph of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of unique alerts counted by interval
        """
        logger.info(f"get_audit_log_unique_alerts_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_Alert", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Alerts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_resource_type_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique Resource Types graph of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of unique Resource Types counted by interval
        """
        logger.info(f"get_audit_log_unique_resource_type_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_ResourceType", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Resource Types: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_regions_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique Regions graph of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of unique Regions counted by interval
        """
        logger.info(f"get_audit_log_unique_regions_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_Region", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Regions: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_unique_errors_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get data that generated the Unique Errors graph of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of unique Errors counted by interval
        """
        logger.info(f"get_audit_log_unique_errors_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogTS_Error", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Errors: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_alert_box_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get active High-Priority Alerts of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of Active High-Priority Alerts
        """
        logger.info(f"get_audit_log_alert_box_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            AuditLogFilters.PROJECT_ID: [
                {
                    "value": gcp_project_id,
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
                    "value": "GCP"
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

    def get_audit_log_logs_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get Audit log logs collected of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project ID
        :return: List of User events
        """
        logger.info(f"get_audit_log_logs_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogDetails", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Audit logs: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_user_details_by_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get Audit log user details collected of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project ID
        :return: List of User events
        """
        logger.info(f"get_audit_log_user_details({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogDetailsByIdentity", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"User details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_audit_log_api_error_events_by_gcp_project_id(self, gcp_project_id: str) -> list:
        """
        Helper function to get API Error Events collected of a specific gcp project inside Audit log page

        :param gcp_project_id: GCP Project Id
        :return: List of API Error Events
        """
        logger.info(f"get_audit_log_api_error_events_by_gcp_project_id({gcp_project_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": AuditLogFilters.PROJECT_ID,
                    "value": gcp_project_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="GCPAuditLogErrorInfo", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"API Error Events: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def wait_until_specific_event_resource_appear(self, gcp_project_id: str, resource_name: str, method_name: str, timeout: int = 3600) -> bool:
        """
        Helper function to wait until a specfic event to appear after new AuditLogs logs pushed to Lacework Database by checking event_name and resource_name

        :param gcp_project_id: GCP Project Id
        :param resource_name: Resource name to check
        :param method_name: Name of the expected method
        :param timeout: Maximum time to wait until new logs to appear
        """
        logger.info(f"wait_until_specific_event_resource_appear({gcp_project_id}:{resource_name}, {method_name=})")
        start_time = time.monotonic()
        found = False
        timed_out = False
        while not found and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            auditlog_log = self.get_audit_log_logs_by_gcp_project_id(gcp_project_id)
            for log in auditlog_log:
                if log['METHOD_NAME'] == method_name and resource_name in log['RESOURCE_NAME']:
                    found = True
            if not found:
                time.sleep(60)
        if found:
            logger.info(f"Event {method_name} with {resource_name=} appears inside AuditLog logs after {time_passed} seconds")
            return found
        raise TimeoutError(f"Event {method_name} with {resource_name=} did not appear inside Lacework after {timeout} seconds")

    def wait_until_gcp_audit_log_account_added_after_timestamp_with_project_id(self, timestamp: datetime, gcp_project_id: str, timeout: int = 600) -> Any | None:
        """
        Helper function to wait until a GCP AuditLog integration with a specific projectID created with and added after a specific timestamp

        :param gcp_project_id: GCP Project Id
        :param timestamp: A fixed timestamp
        :param timeout: Maximum time to wait

        :return: Account found
        """
        logger.info(f"wait_until_gcp_audit_log_account_added_after_timestamp_with_project_id({gcp_project_id}=)")
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
                if cloud_account['TYPE'] == "GCP_AL_PUB_SUB" and cloud_account['CREATED_OR_UPDATED_TIME'] > timestamp:
                    intg_guid = cloud_account['INTG_GUID']
                    current_account_info = integration_client.get_cloud_account_by_intg_guid(intg_guid).json()['data'][0]
                    if current_account_info['DATA']['PROJECT_ID'] == gcp_project_id:
                        found = True
                        account_found = current_account_info
                        break
            if not found:
                time.sleep(60)
        if found:
            logger.info(f"GCP AuditLog integration with {gcp_project_id=} appears after {time_passed} seconds, {account_found=}")
            return account_found
        raise TimeoutError(f"GCP AuditLog integration with {gcp_project_id=} does not appear after {time_passed} seconds")
