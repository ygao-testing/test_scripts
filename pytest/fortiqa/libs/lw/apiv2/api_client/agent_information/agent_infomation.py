import logging
import requests


log = logging.getLogger(__name__)


class AgentInformation:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/AgentInfo"

    def search_agent_info(self, payload: dict) -> requests.Response:
        """
        Retrieve information about all agents that meet filters
        :param payload: Search agent access tokens payload. timefilter, filters and returns
        :return: Response
        """
        log.info("search_agent_info()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response
