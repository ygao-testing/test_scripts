import json
import logging
import time

from copy import deepcopy
from datetime import datetime
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.payloads import CloudTrailFilters, AlertMetadataFilter
from fortiqa.libs.lw.apiv1.helpers.cloud_logs.cloud_logs_helpers import CloudLogsHelper

logger = logging.getLogger(__name__)


class CloudTrailHelper(CloudLogsHelper):
    def __init__(self, user_api, fix_timestamp: datetime = datetime.now()):
        super().__init__(user_api=user_api, fix_timestamp=fix_timestamp)

    def list_all_cloudtrail_accounts(self):
        """Helper function to list all AWS cloudtrail Accounts"""
        logger.info("list_all_cloudtrail_accounts()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailAccountsList", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All onboared CloudTrail accounts: {json.dumps(query_card_response.json(), indent=2)}")
        # Response data:
        # {
        #     "ok": true,
        #     "data": [
        #         {
        #             "RECIPIENT_ACCOUNT_ID": "991966387703",
        #             "RECIPIENT_ACCOUNT_ALIAS": "",
        #             "START_TIME": 1741194000000
        #         }
        #     ]
        # }
        return query_card_response.json()['data']

    def get_cloud_trail_event_data_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Events graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of event cound data
        """
        logger.info(f"get_cloud_trail_event_data({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailRawEventTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Events data: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_usernames_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique Usernames graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique usernames counted by interval
        """
        logger.info(f"get_cloud_trail_unique_usernames_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailUserTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Usernames: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_accounts_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique Accounts graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique accounts counted by interval
        """
        logger.info(f"get_cloud_trail_unique_accounts_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailDistinctAccountTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Accounts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_services_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique Services graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique services counted by interval
        """
        logger.info(f"get_cloud_trail_unique_services_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailDistinctServiceTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Services: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_alerts_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique Alerts graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique alerts counted by interval
        """
        logger.info(f"get_cloud_trail_unique_alerts_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailAlertTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Alerts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_apis_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique APIs graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique APIs counted by interval
        """
        logger.info(f"get_cloud_trail_unique_apis_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailDistinctApiTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique APIs: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_regions_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique Regions graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique Regions counted by interval
        """
        logger.info(f"get_cloud_trail_unique_regions_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailDistinctRegionTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Regions: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_unique_errors_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get data that generated the Unique Errors graph of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of unique Errors counted by interval
        """
        logger.info(f"get_cloud_trail_unique_errors_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="CloudTrailDistinctErrorTS", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Errors: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_alert_box_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get active High-Priority Alerts of a specific AWS account inside CloudTrail page

        :param aws_account_id: AWS account ID
        :return: List of Active High-Priority Alerts
        """
        logger.info(f"get_cloud_trail_alert_box_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            CloudTrailFilters.AWS_ACCOUNT_CALLEE: [
                {
                    "value": aws_account_id,
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
                    "value": "AWS"
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

    def get_cloud_trail_logs_by_aws_account(self, aws_account_id: str) -> list:
        r"""
        Helper function to get cloudtrail logs collected of a specific AWS account inside CloudTrail page

        Example Output entry:
        [
            {
                "RECIPIENT_ACCOUNT_ID": "183631341284",
                "RECIPIENT_ACCOUNT_ALIAS": null,
                "USER_IDENTITY_ACCOUNT": "183631341284",
                "AWS_REGION": "us-east-2",
                "EVENT_SOURCE": "kms.amazonaws.com",
                "EVENT_NAME": "Decrypt",
                "START_TIME": 1741143600000,
                "USER_NAME": "AWSService/183631341284:cloudtrail.amazonaws.com",
                "SOURCE_IP_ADDRESS": "cloudtrail.amazonaws.com",
                "S3_URL": "s3://lacework-ct-bucket-e2acf592/AWSLogs/183631341284/CloudTrail/us-east-2/2025/03/05/183631341284_CloudTrail_us-east-2_20250305T0350Z_YxExDfp8lpxdvlos.json.gz",
                "COUNT": "1",
                "REQUEST_PARAMETERS": null,
                "USER_IDENTITY": "{\"invokedBy\":\"cloudtrail.amazonaws.com\",\"type\":\"AWSService\"}",
                "PRINCIPAL_ID": null
            }
        ]

        :param aws_account_id: AWS account ID
        :return: List of CloudTrail logs
        """
        logger.info(f"get_cloud_trail_logs_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        logger.info(f"Payload: {json.dumps(payload, indent=2)}")
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card237", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"CloudTrail logs: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def wait_until_new_cloud_trail_log_appear(self, aws_account_id: str, aws_s3_bucket_name: str, timeout: int = 7200) -> bool:
        """
        Helper function to wait until new CloudTrail logs pushed to Lacework Database by checking S3 bucket name
        When onboarding a new AWS integration, it will create a new S3 bucket to store the CloudTrail logs

        :param aws_account_id: AWS Account ID
        :param aws_s3_bucket_name: AWS S3 Bucket created by onboarding
        :param timeout: Maximum time to wait until new logs to appear
        """
        logger.info(f"wait_until_new_cloud_trail_log_appear({aws_account_id}:{aws_s3_bucket_name})")
        start_time = time.monotonic()
        found = False
        timed_out = False
        while not found and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            cloud_trail_log = self.get_cloud_trail_logs_by_aws_account(aws_account_id)
            for log in cloud_trail_log:
                if aws_s3_bucket_name in log["S3_URL"]:
                    found = True
            if not found:
                time.sleep(60)
        if found:
            logger.info(f"CloudTrail logs inside {aws_s3_bucket_name} of {aws_account_id} appear inside Lacework after {time_passed} seconds")
            return found
        raise TimeoutError(f"CloudTrail logs inside {aws_s3_bucket_name} of {aws_account_id} did not appear inside Lacework after {timeout} seconds")

    def wait_until_specific_event_log_appear(self, aws_account_id: str, aws_s3_bucket_name: str, event_name: str, timeout: int = 1800) -> bool:
        """
        Helper function to wait until a specfic event to appear after new CloudTrail logs pushed to Lacework Database by checking S3 bucket name
        When onboarding a new AWS integration, it will create a new S3 bucket to store the CloudTrail logs

        :param aws_account_id: AWS Account ID
        :param aws_s3_bucket_name: AWS S3 Bucket created by onboarding
        :param event_name: Name of the expected event
        :param timeout: Maximum time to wait until new logs to appear
        """
        logger.info(f"wait_until_specific_event_log_appear({aws_account_id}:{aws_s3_bucket_name}, {event_name=})")
        start_time = time.monotonic()
        found = False
        timed_out = False
        while not found and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            cloud_trail_log = self.get_cloud_trail_logs_by_aws_account(aws_account_id)
            for log in cloud_trail_log:
                if log['EVENT_NAME'] == event_name and aws_s3_bucket_name in log['S3_URL']:
                    found = True
            if not found:
                time.sleep(60)
        if found:
            logger.info(f"Event {event_name} appears inside CloudTrail logs after {time_passed} seconds")
            return found
        raise TimeoutError(f"Event {event_name} did not appear inside Lacework after {timeout} seconds")

    def get_cloud_trail_user_details_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get User details collected of a specific AWS account inside CloudTrail page

        Example Output entry:
        [
            {
                "USER_NAME": "AssumedRole/183631341284:lw-iam-5205bb97",
                "AWS_REGION": "eu-central-1",
                "ACCOUNT_NUMBER": "183631341284",
                "ACCOUNT_ALIAS": null,
                "USER_IDENTITY_ACCOUNT": "183631341284",
                "LOCATION_CITY": "Boardman",
                "LOCATION_REGION": "Oregon",
                "LOCATION_COUNTRY_NAME": "United States",
                "MFA": "false",
                "FIRST_SEEN_TIME": 1741176000000,
                "LAST_SEEN_TIME": 1741179600000
            }
        ]

        :param aws_account_id: AWS account ID
        :return: List of User details
        """
        logger.info(f"get_cloud_trail_user_details_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card245", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"User details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_user_events_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get User events collected of a specific AWS account inside CloudTrail page

        Example Output entry:
        [
            {
                "EVENT_SOURCE": "wafv2.amazonaws.com",
                "USER_NAME": "AssumedRole/183631341284:lw-iam-5205bb97",
                "EVENT_NAME": "ListRegexPatternSets",
                "LACEWORK_ALERT_COUNT": "0",
                "CLOUDTRAIL_RAW_EVENT_COUNT": "18",
                "ERROR_COUNT": "0"
            }
        ]

        :param aws_account_id: AWS account ID
        :return: List of User events
        """
        logger.info(f"get_cloud_trail_user_events_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card241", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"User events: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_cloud_trail_api_error_events_by_aws_account(self, aws_account_id: str) -> list:
        """
        Helper function to get API Error Events collected of a specific AWS account inside CloudTrail page

        Example Output entry:
        [
            {
                "SERVICE": "sagemaker.amazonaws.com",
                "ERROR_CODE": "ValidationException",
                "USER_NAME": "AssumedRole/183631341284:lw-iam-5205bb97",
                "API": "ListEdgePackagingJobs",
                "ERROR_COUNT": "6"
            }
        ]

        :param aws_account_id: AWS account ID
        :return: List of API Error Events
        """
        logger.info(f"get_cloud_trail_api_error_events_by_aws_account({aws_account_id=})")
        payload = deepcopy(self.payload_template)
        payload['NavigationKey'] = {
            "filters": [
                {
                    "field": CloudTrailFilters.AWS_ACCOUNT_CALLEE,
                    "value": aws_account_id,
                    "type": "eq"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card246", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"API Error Events: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']
