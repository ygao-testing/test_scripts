import logging
import requests


log = logging.getLogger(__name__)


class Datasources:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/Datasources"

    def get_datasources(self) -> requests.Response:
        """
        List all available datasources for the current user
        :return: Response
        """
        log.info("get_datasources()")
        response = self._user_api.get(url=f"{self._api_url}")
        return response

    def get_datasource_detail(self, datasource: str) -> requests.Response:
        """
        Get details about a single datasource
        :param datasource: Name of the datasource
        :return: Response
        """
        log.info(f"get_datasource_detail() for {datasource=}")
        response = self._user_api.get(url=f"{self._api_url}/{datasource}")
        return response

    def search_datasources(self, payload: dict) -> requests.Response:
        """
        Search the datasources
        :param payload: Search datasources payload, timeFilter, filters and returns
        :return: Response
        """
        log.info("search_datasources()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response
