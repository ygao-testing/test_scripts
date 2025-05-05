import logging
import requests

from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


class InventoryV1:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/Inventory"

    def track_inventory_scan_status(self, provider: str) -> requests.Response:
        """Checks the inventory scan status for a specified cloud provider.

        Args:
            provider (str): The cloud provider (e.g., 'AWS', 'Azure', 'GCP').

        Returns:
            requests.Response: The API response with the scan status for the provider.
        """
        logger.info("track_inventory_scan_status()")
        logger.info(f"Checking scan status for {provider} ")
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
        logger.info(f" V1 status code: {response_status_code}")
        logger.info(f"V1 response body {response.text}")
        if response_status_code != 200:
            logger.info(f"Track inventory scan status API stuse code = {response_status_code} trying again")
            response = self.track_inventory_scan_status(provider)
            response_status_code = response.status_code
            logger.info(f" V1 status code: {response_status_code}")
            logger.info(f"v1 response body {response.text}")
            if response_status_code != 200:
                raise Exception(f"Track inventory scan status API stuse code = {response_status_code}")
        api_response_json = check_and_return_json_from_response(response)
        result = {
            'status': api_response_json['data'][0]['status'],
            'details': api_response_json['data'][0]['details']
            }
        return result
