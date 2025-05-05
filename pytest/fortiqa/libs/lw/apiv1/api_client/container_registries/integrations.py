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
        self._api_url = f"{api_v1_client.url}/integrations/containerRegistries"

    def get_container_registries(self) -> requests.Response:
        """Retrieves container registries and their info from the API.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("get_container_registries()")
        response = self._user_api.get(url=f"{self._api_url}?details=true")
        logger.debug(f"Container registries response: {response.text}")
        return response

    def get_container_registry_by_intg_guid(self, intg_guid: str) -> requests.Response:
        """Retrieves the container registry by intgGuid from the API.

        Args:
            intg_guid: Integration GUID of the container registry.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info(f"get_container_registry_by_intg_guid() for {intg_guid}")
        response = self._user_api.get(url=f"{self._api_url}/{intg_guid}")
        logger.debug(f"Container registry with {intg_guid}: {response.text}")
        return response

    def add_container_registry(self, payload: dict) -> requests.Response:
        """Add container registry using API V1.

        Args:
            payload: Container registry configurations.
            example:
                {
                    "TYPE": "CONT_VULN_CFG",
                    "ENABLED": 1,
                    "IS_ORG": 0,
                    "NAME": "test",
                    "DATA": {
                        "ACCESS_KEY_CREDENTIALS": {
                            "ACCESS_KEY_ID": "xxxxxx",
                            "SECRET_ACCESS_KEY": "xxxxx"
                        },
                        "AWS_AUTH_TYPE": "AWS_ACCESS_KEY",
                        "REGISTRY_TYPE": "AWS_ECR",
                        "REGISTRY_DOMAIN": "{AWS_ACCOUNT_ID}.dkr.ecr.us-west-1.amazonaws.com",
                        "LIMIT_BY_TAG": [],
                        "LIMIT_BY_LABEL": [],
                        "LIMIT_BY_REP": [],
                        "LIMIT_NUM_IMG": 5,
                        "NON_OS_PACKAGE_EVAL": true
                    },
                    "PROPS": {
                        "tags": "AWS_ECR"
                    },
                    "ENV_GUID": ""
                }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("add_container_registry()")
        response = self._user_api.post(url=self._api_url, payload=payload)
        logger.debug(f"Add container registry response: {response.text}")
        return response

    def wait_until_container_registry_success(self, intg_guid: str, timeout: int = 3000) -> None:
        """
        Wait until a container registry turns Success status

        Args:
            intg_guid: Integration GUID of the Container Registry
            timeout: Max time until we wait for the container registry turns to Success in Lacework.

        Returns: None
        Raises: TimeoutError if the Container Registry's status is not Success after timeout
        """
        success = False
        start_time = time.monotonic()
        timed_out = False
        while not timed_out and not success:
            time.sleep(60)
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            container_registry_info = self.get_container_registry_by_intg_guid(intg_guid).json()['data'][0]
            if container_registry_info['STATE']['ok'] and container_registry_info['STATE']['details']['errorMap']:
                success = True
        if not success:
            raise TimeoutError(
                f'Container Registry {intg_guid} does not turn to Success status after {time_passed} secs'
                f'Last Container Registry info: {container_registry_info}'
            )
        logger.info(f"It took {time_passed} secs until the Container Registry changes to Success status")

    def wait_until_container_scanned(self, intg_guid: str, ecr_repo_name: str, timeout: int = 3000) -> None:
        """
        Wait until a container registry turns Success status

        Args:
            intg_guid: Integration GUID of the Container Registry
            ecr_repo_name: Repo inside ECR
            timeout: Max time until we wait for the container registry turns to Success in Lacework.

        Returns: None
        Raises: TimeoutError if the Container Registry's status is not Success after timeout
        """
        scanned = False
        start_time = time.monotonic()
        timed_out = False
        while not timed_out and not scanned:
            time.sleep(60)
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            container_registry_info = self.get_container_registry_by_intg_guid(intg_guid).json()['data'][0]
            if container_registry_info['STATE']['ok'] and ecr_repo_name in container_registry_info['STATE']['details']['errorMap']:
                scanned = True
        if not scanned:
            raise TimeoutError(
                f'Container Registry {intg_guid} does not scan {ecr_repo_name} after {time_passed} secs'
                f'Last Container Registry info: {container_registry_info}'
            )
        logger.info(f"It took {time_passed} secs until the Container Registry to scan {ecr_repo_name}")

    def delete_container_registry(self, intg_guid: str) -> requests.Response:
        """Delete agentless cloud account using API V1.

        Args:
            intg_guid: Integration GUID of the Container Registry

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info(f"delete_container_registry() for {intg_guid}")
        response = self._user_api.delete(url=f"{self._api_url}/{intg_guid}")
        logger.debug(f"Delete container registry status: {response.text}")
        return response
