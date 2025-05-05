import json
import logging
from typing import Optional

import requests


log = logging.getLogger(__name__)


class LaceworkResource:
    """Base class to interact with Lacework resources.

    This class provides common methods to interact with various Lacework resources
    such as listing, creating, searching, retrieving details, deleting, and updating resources.
    Different resource classes can inherit from this class to interact with specific resources.
    """

    def __init__(self, user_api) -> None:
        """
        Initialize the LaceworkResource with the user API.

        :param user_api: The user API instance to interact with the Lacework API.
        """
        self._user_api = user_api
        # To be set by the child class
        self._api_url: Optional[str] = None
        self._resource_type: Optional[str] = None
        self._resource_id: Optional[str] = None
        self._resource_payload = None
        self._id_field: Optional[str] = None

    def list_all_resource(self) -> requests.Response:
        """
        Get a list of all resources for the current user.

        :return: Response object containing the list of resources.
        """
        log.info("list_all_resource()")
        response = self._user_api.get(url=f"{self._api_url}")
        return response

    def create_resource(self) -> requests.Response:
        """
        Create a resource by specifying parameters in the request body.

        :return: Response object containing the result of the creation operation.
        """
        log.info("create_resource() with payload: %s", json.dumps(self._resource_payload, indent=2))
        response = self._user_api.post(url=f"{self._api_url}", payload=self._resource_payload)
        return response

    def search_resource(self, payload: dict) -> requests.Response:
        """
        Search resources based on the provided payload.

        :param payload: Dictionary containing search parameters.
        :return: Response object containing the search results.
        """
        log.info("search_resource()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response

    def get_resource_details(self) -> requests.Response:
        """
        Get details of a specific resource.

        :return: Response object containing the resource details.
        """
        log.info("get %s details for id: %s", self._resource_type, self._resource_id)
        response = self._user_api.get(url=f"{self._api_url}/{self._resource_id}")
        return response

    def find_id_by_name(self, resource_name: str) -> str:
        """
        Find the resource id by resource name.

        :param resource_name: Resource name to search for.
        :return: Resource ID if found, otherwise None.
        """
        log.info("find %s id by name: %s", self._resource_type, resource_name)
        response = self.list_all_resource()
        resources = json.loads(response.text)["data"]
        for resource in resources:
            if resource_name == resource.get("name", None):
                return resource[self._id_field]
        return ""

    def find_id_by_title(self, resource_title: str) -> str:
        """
        Find the resource id by resource title.

        :param resource_title: Resource title to search for.
        :return: Resource ID if found, otherwise None.
        """
        log.info("find %s id by title: %s", self._resource_type, resource_title)
        response = self.list_all_resource()
        resources = json.loads(response.text)["data"]
        for resource in resources:
            if resource_title == resource.get("title", None):
                return resource[self._id_field]
        return ""

    def delete_resource(self, resource_id: Optional[str] = None,
                        resource_name: Optional[str] = None) -> requests.Response:
        """
        Delete a specific resource by resource id or resource name.

        :param resource_id: Resource ID to delete. If not provided, uses the instance's resource ID.
        :return: Response object containing the result of the deletion operation.
        """
        if resource_id is None:
            if self._resource_id:
                resource_id = self._resource_id
            elif resource_name:
                # search for resource id by name
                resource_id = self.find_id_by_name(resource_name)

        # assert resource_id, "Resource ID not found, please provide resource_id or resource_name"
        log.info("delete %s for resource_id=%s", self._resource_type, resource_id)
        response = self._user_api.delete(url=f"{self._api_url}/{resource_id}")
        if response.status_code != 204:
            log.error("Failed to delete %s for resource_id=%s, response=%s", self._resource_type, resource_id, response.text)
        return response

    def update_resource(self, payload: dict, resource_id=None) -> requests.Response:
        """
        Update a specific resource.

        :param payload: Dictionary containing update parameters.
        :return: Response object containing the result of the update operation.
        """
        if not resource_id:
            resource_id = self._resource_id
        log.info("update %s for id %s, payload=%s", self._resource_type, resource_id, payload)
        response = self._user_api.patch(url=f"{self._api_url}/{resource_id}", payload=payload)
        return response
