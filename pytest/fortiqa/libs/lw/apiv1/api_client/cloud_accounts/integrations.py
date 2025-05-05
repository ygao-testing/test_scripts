import logging
import requests
import time

from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client

logger = logging.getLogger(__name__)


class Integrations:
    """A class to interact with the integrations V1 API."""

    def __init__(self, api_v1_client: ApiV1Client) -> None:
        """Initializes the AccountSetting class.

        Args:
            api_v1_client (api_v1_client): An instance of the API v1 client for sending requests.
        """
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/integrations/cloudAccounts"

    def get_cloud_accounts(self) -> requests.Response:
        """Retrieves the cloud accounts from the API.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("get_cloud_accounts()")
        response = self._user_api.get(url=self._api_url)
        logger.debug(f"Cloud accounts response: {response.text}")
        return response

    def get_cloud_account_by_intg_guid(self, intg_guid: str) -> requests.Response:
        """Retrieves the cloud account by intgGuid from the API.

        Args:
            intg_guid: Integration GUID of the cloud account.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info(f"get_cloud_account_by_intg_guid() for {intg_guid}")
        response = self._user_api.get(url=f"{self._api_url}/{intg_guid}")
        logger.debug(f"Cloud account response: {response.text}")
        return response

    def add_agentless_cloud_account(self, payload: dict) -> requests.Response:
        """Add agentless cloud account using API V1.

        Args:
            payload: Agentless cloud account configurations.
            example:
                {
                    "TYPE": "AWS_SIDEKICK",
                    "ENABLED": 1,
                    "IS_ORG": 0,
                    "NAME": "test",
                    "DATA": {
                        "AWS_ACCOUNT_ID": "xxx",
                        "SCAN_FREQUENCY": 6,
                        "SCAN_HOST_VULNERABILITIES": true,
                        "SCAN_CONTAINERS": true,
                        "SCAN_STOPPED_INSTANCES": true,
                        "SCAN_MULTI_VOLUME": false,
                        "SCAN_SHORT_LIVED_INSTANCES": false
                    },
                    "ENV_GUID": ""
                }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("add_agentless_cloud_account()")
        response = self._user_api.post(url=self._api_url, payload=payload)
        logger.debug(f"Add agentless cloud accounts response: {response.text}")
        return response

    def delete_agentless_cloud_account(self, intg_guid: str) -> requests.Response:
        """Delete agentless cloud account using API V1.

        Args:
            intg_guid: Integration GUID of the Agentless AWS account

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info(f"delete_agentless_cloud_account() for {intg_guid}")
        response = self._user_api.delete(url=f"{self._api_url}/{intg_guid}")
        logger.debug(f"Delete agentless cloud accounts status: {response.text}")
        return response

    def wait_until_status_success(self, intg_guid: str, timeout: int = 600) -> None:
        """
        Helper function to wait until a specfic cloud_account to change to success status

        Args:
            intg_guid: Integration GUID of the cloud_account integration
            timeout: Maximum time to wait until new logs to appear
        """
        logger.info(f"wait_until_status_success({intg_guid=})")
        start_time = time.monotonic()
        success = False
        timed_out = False
        while not success and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            cloud_account = self.get_cloud_account_by_intg_guid(intg_guid).json()['data']
            for account in cloud_account:
                if 'STATE' in account and account['STATE']['ok']:
                    success = True
            if not success:
                time.sleep(60)
        if success:
            logger.info(f"Cloud Account integration with {intg_guid=} succeeded after {time_passed} seconds")
            return
        raise TimeoutError(f"Cloud Account integration with {intg_guid=} did not change to success after {time_passed} seconds")
