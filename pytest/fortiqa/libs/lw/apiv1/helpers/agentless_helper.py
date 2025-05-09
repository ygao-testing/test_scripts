import json
import logging
import time

from datetime import datetime, timedelta
from copy import deepcopy
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


class AgentlessHelper:
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

    def return_host_name_according_to_instance_id(self, instance_id: str) -> str:
        """
        Helper function to return the host name in Lacework according to VM's instance_id

        :param instance_id: Instance ID of the host
        :return: Hostname, e.g. ip-10-1-61-83
        """
        logger.info(f"return_host_name_according_to_instance_id(), {instance_id=}")
        all_agentless_hosts = self.list_all_resources_scanned_agentless()
        for resource in all_agentless_hosts:
            if resource['RESOURCE_ID'] == instance_id:
                return resource['RESOURCE_NAME'].split('.')[0]
        logger.error(f"Not find host {instance_id=}")
        raise Exception(f"Not find host {instance_id=}")

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
        first_try = True
        host_found = False
        while first_try or (time.monotonic() < wait_until and not host_found):
            all_agentless_scanned_hosts = self.list_all_resources_scanned_agentless()
            if not first_try:
                time.sleep(240)
            first_try = False
            for host in all_agentless_scanned_hosts:
                if host['RESOURCE_ID'] == instance_id:
                    host_found = True
                    logger.info(f"Host {instance_id} appears")
                    break
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
        first_try = True
        while first_try or (time.monotonic() < wait_until and not host_scanned):
            if not first_try:
                time.sleep(240)
            first_try = False
            all_agentless_scanned_hosts = self.list_all_resources_scanned_agentless()
            for host in all_agentless_scanned_hosts:
                if host['RESOURCE_ID'] == instance_id and host['LAST_SCAN_STATUS'] == 'Scanned':
                    host_scanned = True
                    logger.debug(f"Host {instance_id} was scanned")
                    break
        if not host_scanned:
            raise TimeoutError(
                f'Host {instance_id} was not scanned'
                f'Last list of hosts: {all_agentless_scanned_hosts}'
            )

    def wait_until_container_image_appear(self, image_tag, wait_until: int):
        """Waits for Container image appear for up to 20 minutes.

        Args:
            image_tag: Container Image Tag
            wait_until: Unix time until we wait for container image to appears in Lacework.

        Returns: None
        Raises: TimeoutError if the container image does not appear within time range
        """
        first_try = True
        image_found = False
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and not image_found):
            all_agentless_scanned_resources = self.list_all_resources_scanned_agentless()
            if not first_try:
                time.sleep(240)
            first_try = False
            for resource in all_agentless_scanned_resources:
                image_tags = resource.get("TAGS", {}).get("imageTags", [])
                if any(tag == image_tag for tag in image_tags):
                    image_found = True
                    time_passed = int(time.monotonic() - start_time)
                    logger.debug(f"Container Image with tag {image_tag} appears after {time_passed} secs")
                    break
        if not image_found:
            raise TimeoutError(
                f'Container Image {image_tag} was not returned by API'
                f'Last list of resources: {all_agentless_scanned_resources}'
            )

    def wait_until_container_images_scanned(self, image_tag, wait_until: int):
        """Waits for Container image scanned for up to 20 minutes.

        Args:
            image_tag: Container Image Tag
            wait_until: Unix time until we wait for container image to be scanned in Lacework.

        Returns: None
        Raises: TimeoutError if the container image is not scanned within time range
        """
        first_try = True
        image_scanned = False
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and not image_scanned):
            all_agentless_scanned_resources = self.list_all_resources_scanned_agentless()
            if not first_try:
                time.sleep(240)
            first_try = False
            for resource in all_agentless_scanned_resources:
                image_tags = resource.get("TAGS", {}).get("imageTags", [])
                for tag in image_tags:
                    if tag == image_tag and resource['LAST_SCAN_STATUS'] == "Scanned":
                        image_scanned = True
                        time_passed = int(time.monotonic() - start_time)
                        logger.debug(f"Container Image with tag {image_tag} is scanned after {time_passed} secs")
                        break
                if image_scanned:
                    break
        if not image_scanned:
            raise TimeoutError(
                f'Container Image {image_tag} was not scanned'
                f'Last list of resources: {all_agentless_scanned_resources}'
            )
