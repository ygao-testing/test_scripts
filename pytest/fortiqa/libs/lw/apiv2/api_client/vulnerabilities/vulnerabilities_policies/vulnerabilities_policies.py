import logging
import json
import requests


log = logging.getLogger(__name__)


class VulnerabilityPolicy:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/VulnerabilityPolicies"

    def get_vulnerability_policies(self) -> requests.Response:
        """
        Get a list of vulnerability policies for the current user
        :return: Response
        """
        log.info("get_vulnerability_policies()")
        response = self._user_api.get(url=f"{self._api_url}")
        return response

    def create_vulnerability_policy(self, payload: dict) -> requests.Response:
        """
        Create an vulnerability policy by specifying parameters in the request body
        :param payload: payload to call the endpoint
        :return: Response
        """
        log.info("create_vulnerability_policy()")
        log.info(f"Create payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}", payload=payload)
        return response

    def search_vulnerability_policy(self, payload: dict) -> requests.Response:
        """
        Search vulnerability policies
        :param payload: Search vulnerability policy payload, filters and returns
        :return: Response
        """
        log.info("search_vulnerability_policy()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response

    def get_vulnerability_policy_details(self, policyGuid: str) -> requests.Response:
        """
        Get details of an vulnerability policy
        :param policyGuid: vulnerability policy ID
        """
        log.info(f"get_vulnerability_policy_details() for {policyGuid=}")
        response = self._user_api.get(url=f"{self._api_url}/{policyGuid}")
        return response

    def delete_vulnerability_policy(self, policyGuid: str) -> requests.Response:
        """
        Delete an vulnerability policy
        :param policyGuid: vulnerability policy ID
        """
        log.info(f"delete_vulnerability_policy() for {policyGuid=}")
        response = self._user_api.delete(url=f"{self._api_url}/{policyGuid}")
        return response

    # TODO update vulnerability_policy, need to use PATCH
