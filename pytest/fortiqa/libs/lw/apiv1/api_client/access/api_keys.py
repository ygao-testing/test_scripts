import logging
import requests
import json

from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client

logger = logging.getLogger(__name__)


class APIKeysV1:
    """A class to interact with the API keys API and manage API keys."""

    def __init__(self, api_v1_client: ApiV1Client) -> None:
        """Initializes the APIKeys class.

        Args:
            api_v1_client (api_v1_client): An instance of the API v1 client for sending requests.
        """
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/access/keys"
        self._service_account_api_url = f"{api_v1_client.url}/access/keys/serviceUser"

    def get_api_keys(self) -> requests.Response:
        """Retrieves the API keys from the API.

        Returns:
            requests.Response: The response object from the API call.
            {
                "ok": true,
                "data": [
                    {
                        "keyId": "string",
                        "status": "Active|Inactive",
                        "createdDate": "string",
                        "description": "string",
                        "name": "string",
                        "downloadable": "string",
                        "props": {
                        }
                    }
                    ...
                ]
            }
        """
        logger.info("get api keys")
        response = self._user_api.get(url=self._api_url)
        # logger.debug(f"api keys response: {response.text}")
        return response

    def get_api_keys_for_service_account(self) -> requests.Response:
        """Retrieves the API keys for the service account from the API.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("get api keys for service account")
        response = self._user_api.get(url=self._service_account_api_url)
        result = response.json()
        keys = []
        for item in result["data"]:
            keys += item["keys"]
        result["data"] = keys
        response._content = json.dumps(result).encode('utf-8')
        return response

    def create_api_key(self, payload: dict) -> requests.Response:
        """Creates a new API key.

        Args:
            payload (dict): The payload to create the API key with.
            {
                "name": "string",
                "description": "string"
            }

        Returns:
            requests.Response: The response object from the API call.
            {
                "ok": true,
                "data": {
                    "keyId": "string",
                    "status": "Active|Inactive",
                    "createdDate": "string",
                    "createdUser": "string",
                    "downloadable": true,
                    "props": {}
                }
            }
        """
        logger.info(f"create api key {self._api_url} {payload=}")
        response = self._user_api.post(url=self._api_url, payload=payload)
        logger.debug(f"api key response: {response.text}")
        return response

    def create_api_key_for_service_account(self, payload: dict, service_user_guid) -> requests.Response:
        """Creates a new API key for a service account.

        Args:
            payload (dict): The payload to create the API key with.
            {
                "name": "string",
                "description": "string",
                "account": "string"
            }

        Returns:
            requests.Response: The response object from the API call.
            {
                "keyId": "string",
                "secret": "string",
                "account": "string"
            }
        """
        logger.info(f"create api key for service account {self._api_url} {payload=}")
        response = self._user_api.post(url=f"{self._api_url}/{service_user_guid}", payload=payload)
        logger.debug(f"api key response: {response.text}")
        return response

    def download_api_key(self, payload: dict) -> requests.Response:
        """Downloads the API key.

        Args:
            payload (dict): The payload to download the API key with.
            {
                "KEY_ID": "string"
            }

        Returns:
            requests.Response: The response object from the API call.
            {
                "keyId": "string",
                "secret": "string",
                "account": "string"
            }
        """
        logger.info("download api key")
        base_url = self._user_api.url
        response = self._user_api.post(url=f"{base_url}/downloads/keys", payload=payload)
        logger.debug(f"api key response: {response.text}")
        return response

    def edit_api_key(self, key_id: str, payload: dict) -> requests.Response:
        """Edits the API key.

        Args:
            payload (dict): The payload to edit the API key with.
            {
                "status": "Inactive|Active",
            }

        Returns:
            requests.Response: The response object from the API call.
            200
        """
        logger.info(f"edit api key {key_id}")
        response = self._user_api.put(url=f"{self._user_api.url}/access/key/{key_id}", payload=payload)
        logger.debug(f"api key response: {response.text}")
        return response

    def delete_api_key(self, key_id: str) -> requests.Response:
        """Deletes the API key.

        Args:
            key_id (str): The ID of the API key to delete.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info(f"delete api key {key_id}")
        delete_url = f"{self._user_api.url}/access/key"  # this endpoint use 'key', not 'keys'
        response = self._user_api.delete(url=f"{delete_url}/{key_id}")
        logger.debug(f"delete api key response: {response}")
        return response

    def create_service_account(self, payload: list) -> requests.Response:
        """Creates a new service account.

        Args:
            payload (list): The payload to create the service account with.
            [
              {
                "name": "string",
                "description": "string"
              }
            ]

        Returns:
            requests.Response: The response object from the API call.
            {
                "ok": true,
                "data": [
                    {
                        "name": "fcsqa-test",
                        "description": "test",
                        "userGuid": "",
                        "userEnabled": 0,
                        "serviceUserId": "",
                        "apiKeys": [
                            {
                                "createdDate": "",
                                "keyId": "",
                                "createdUser": "",
                                "status": "Active"
                            }
                        ],
                        "type": "SERVICE_USER",
                        "lastLoginTime": 0
                    }
                ]
            }
        """
        logger.info(f"create service account with payload: {payload}")
        url = f"{self._user_api.url}/account/serviceUsers"
        response = self._user_api.post(url=url, payload=payload)
        logger.debug(f"create service account response: {response.text}")
        return response

    def delete_service_account(self, user_guid: str) -> requests.Response:
        """Deletes a service account user.

        Args:
            user_guid (str): The user GUID of the service account to delete.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info(f"delete service account with user_guid: {user_guid}")
        url = f"{self._user_api.url}/account/users/{user_guid}"
        response = self._user_api.delete(url=url)
        logger.debug(f"delete service account response: {response}")
        return response
