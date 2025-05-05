import logging
import requests
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


class InventoryV2:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/Inventory"

    def search_inventory(self, payload: dict) -> requests.Response:
        """
        Retrieve information about resources in your cloud integrations
        :param payload: Search Inventory payload
        :return: Response
        """
        logger.info("search_inventory()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response

    def track_inventory_scan_status(self, provider: str) -> requests.Response:
        """Checks the inventory scan status for a specified cloud provider.

        Args:
            provider (str): The cloud provider (e.g., 'AWS', 'Azure', 'GCP').

        Returns:
            requests.Response: The API response with the scan status for the provider.
        """
        logger.info("track_inventory_scan_status()")
        logger.info(f"Checking scan  status for {provider} ")
        response = self._user_api.get(url=f"{self._api_url}/scan?csp={provider}")
        return response

    def get_scan_status(self, provider: str) -> dict[str, str]:
        """Retrieves the scan status and details for a specified cloud provider.

        Args:
            provider (str): Name of the cloud provider (e.g., "AWS", "Azure, Gcp").

        Returns:
            dict[str, str]: Dictionary containing:
                - "status": Scan status (e.g., "scanning", "available", "pending).
                - "details": Additional information about the scan.

        Raises:
            Exception: If the API response code is not 200 after two attempts.
        """
        response = self.track_inventory_scan_status(provider)
        response_status_code = response.status_code
        logger.info(f"status code: {response_status_code}")
        logger.info(f"response body {response.text}")
        if response_status_code != 200:
            logger.info(f"Track inventory scan status API stuse code = {response_status_code} trying again")
            response = self.track_inventory_scan_status(provider)
            response_status_code = response.status_code
            logger.info(f"status code: {response_status_code}")
            logger.info(f"response body {response.text}")
            if response_status_code != 200:
                raise Exception(f"Track inventory scan status API stuse code = {response_status_code}")
        api_response_json = check_and_return_json_from_response(response)
        result = {
            'status': api_response_json['data']['status'],
            'details': api_response_json['data']['details']
            }
        return result

    def check_if_all_ec2_has_specified_security_group(self, api_response_data: list, target_security_group_id: str) -> bool:
        """Checks if all EC2 instances in the  Inventory  serach API response data have a specified security group.

        Args:
            api_response_data (list): A list of instance data dictionaries from the API response. Each instance dictionary
                should contain 'resourceId' and 'resourceConfig' keys, where 'resourceConfig' includes 'SecurityGroups'.
            target_security_group_id (str): The ID of the target security group to check for in each instance's security groups.

        Returns:
            bool: True if all instances have the specified security group, False if any instance is missing the group.
        """
        instances = api_response_data
        instances_without_target_security_group_id = []  # List to store instances that don't have the target group

        for instance in instances:
            instance_id = instance["resourceId"]
            security_groups = instance["resourceConfig"].get("SecurityGroups", [])

            # Check if the target GroupId exists in the security groups
            has_target_group = any(group["GroupId"] == target_security_group_id for group in security_groups)

            if not has_target_group:
                instances_without_target_security_group_id.append(instance_id)

        # Print results
        if instances_without_target_security_group_id:
            logger.info(f"The following instances do NOT have the security group with GroupId {target_security_group_id}: ")
            for instance_id in instances_without_target_security_group_id:
                logger.info(f"- Instance ID: {instance_id}")
            return False
        else:
            logger.info(f"All instances have the security group with GroupId {target_security_group_id}.")
            return True

    def check_if_all_ec2_lack_specified_security_group(self, api_response_data: list, target_security_group_id: str) -> bool:
        """
        Checks if all EC2 instances in the Inventory Search API response data do NOT have a specified security group.

        Args:
            api_response_data (list): A list of instance data dictionaries from the API response. Each instance dictionary
                should contain 'resourceId' and 'resourceConfig' keys, where 'resourceConfig' includes 'SecurityGroups'.
            target_security_group_id (str): The ID of the security group to check for absence in each instance's security groups.

        Returns:
            bool: True if all instances do NOT have the specified security group, False if any instance has the group.
        """
        instances = api_response_data
        instances_with_target_security_group_id = []  # List to store instances that have the target group

        for instance in instances:
            instance_id = instance["resourceId"]
            security_groups = instance["resourceConfig"].get("SecurityGroups", [])

            # Check if the target GroupId exists in the security groups
            has_target_group = any(group["GroupId"] == target_security_group_id for group in security_groups)

            if has_target_group:
                instances_with_target_security_group_id.append(instance_id)

        if instances_with_target_security_group_id:
            logger.info(f"The following instances have the security group with GroupId {target_security_group_id}: ")
            for instance_id in instances_with_target_security_group_id:
                logger.info(f"- Instance ID: {instance_id}")
            return False
        else:
            logger.info(f"No instances have the security group with GroupId {target_security_group_id}.")
            return True
