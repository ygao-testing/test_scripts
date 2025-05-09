import json
import logging
import time

from datetime import datetime, timedelta
from copy import deepcopy
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


class ContainerRegistryHelper:
    def __init__(self, user_api, agent_deployment_timestamp: datetime = datetime.now()):
        self.user_api = user_api
        start_date = agent_deployment_timestamp - timedelta(hours=5)
        end_date = agent_deployment_timestamp + timedelta(hours=5)
        self.payload_template = {
            "ParamInfo": {
                "StartTimeRange": int(start_date.timestamp() * 1000.0),
                "EndTimeRange": int(end_date.timestamp() * 1000.0),
                "EnableEvalDetailsMView": True
            },
        }
        logger.debug(f"Agentless generic payload: {self.payload_template}")

    def list_all_agentless_accounts(self) -> list:
        """Helper function to list all agentless cloud accounts"""
        logger.info("list_all_agentless_accounts()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"All agentless accounts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_all_resources_scanned_agentless(self) -> list:
        """Helper function to list all resources scanned agentless"""
        logger.info("list_all_resources_scanned_agentless()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"All resources scanned agentless: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def wait_until_cloud_account_appear(self, aws_account_id, wait_until: int):
        """Waits for agentless aws account appears for up to 20 minutes.

        Args:
            aws_account_id: AWS account ID
            wait_until: Unix time until we wait for aws_account to appears in Lacework.

        Returns: None
        Raises: TimeoutError if aws account does not appear within time range
        """
        aws_account_found = False
        while time.monotonic() < wait_until and not aws_account_found:
            all_agentless_accounts = self.list_all_agentless_accounts()
            for account in all_agentless_accounts:
                if account['ACCOUNT'] == aws_account_id:
                    aws_account_found = True
        if not aws_account_found:
            raise TimeoutError(
                f'AWS Account {aws_account_id} was not returned by API'
                f'Last list of accounts: {all_agentless_accounts}'
            )

    def wait_until_host_appear(self, instance_id, wait_until: int):
        """Waits for host appear for up to 20 minutes.

        Args:
            instance_id: Host instance ID
            wait_until: Unix time until we wait for host to appears in Lacework.

        Returns: None
        Raises: TimeoutError if host does not appear within time range
        """
        host_found = False
        while time.monotonic() < wait_until and not host_found:
            all_agentless_scanned_hosts = self.list_all_resources_scanned_agentless()
            for host in all_agentless_scanned_hosts:
                if host['RESOURCE_ID'] == instance_id:
                    host_found = True
            time.sleep(30)
        if not host_found:
            raise TimeoutError(
                f'Host {instance_id} was not returned by API'
                f'Last list of hosts: {all_agentless_scanned_hosts}'
            )

    def wait_until_host_scanned(self, instance_id, wait_until: int):
        """Waits for host scanned agentlessly for up to 20 minutes.

        Args:
            instance_id: Host instance ID
            wait_until: Unix time until we wait for host scanned agentlessly.

        Returns: None
        Raises: TimeoutError if host is scanned agentlessly until timeout
        """
        host_scanned = False
        while time.monotonic() < wait_until and not host_scanned:
            all_agentless_scanned_hosts = self.list_all_resources_scanned_agentless()
            for host in all_agentless_scanned_hosts:
                if host['RESOURCE_ID'] == instance_id and host['LAST_SCAN_STATUS'] == 'Scanned':
                    host_scanned = True
            time.sleep(30)
        if not host_scanned:
            raise TimeoutError(
                f'Host {instance_id} was not scanned'
                f'Last list of hosts: {all_agentless_scanned_hosts}'
            )
