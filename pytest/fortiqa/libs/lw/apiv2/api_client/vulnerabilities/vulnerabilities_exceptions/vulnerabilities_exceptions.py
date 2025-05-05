import logging
import json
import requests


log = logging.getLogger(__name__)


class VulnerabilityException:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/VulnerabilityExceptions"

    def get_vulnerability_exceptions(self) -> requests.Response:
        """
        Get a list of vulnerability exceptions for the current user
        :return: Response
        """
        log.info("get_vulnerability_exceptions()")
        response = self._user_api.get(url=f"{self._api_url}")
        return response

    def create_vulnerability_exception(self, payload: dict) -> requests.Response:
        """
        Create an vulnerability exception by specifying parameters in the request body
        :param payload: payload to call the endpoint
        :return: Response
        """
        log.info("create_vulnerability_exception()")
        log.info(f"Create payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}", payload=payload)
        return response

    def search_vulnerability_exception(self, payload: dict) -> requests.Response:
        """
        Search vulnerability exceptions
        :param payload: Search vulnerability exception payload, filters and returns
        :return: Response
        """
        log.info("search_vulnerability_exception()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response

    def get_vulnerability_exception_details(self, exceptionGuid: str) -> requests.Response:
        """
        Get details of an vulnerability exception
        :param exceptionGuid: vulnerability exception ID
        """
        log.info(f"get_vulnerability_exception_details() for {exceptionGuid=}")
        response = self._user_api.get(url=f"{self._api_url}/{exceptionGuid}")
        return response

    def delete_vulnerability_exception(self, exceptionGuid: str) -> requests.Response:
        """
        Delete an vulnerability exception
        :param exceptionGuid: vulnerability exception ID
        """
        log.info(f"delete_vulnerability_exception() for {exceptionGuid=}")
        response = self._user_api.delete(url=f"{self._api_url}/{exceptionGuid}")
        return response

    # TODO update vulnerability_exception, need to use PATCH
