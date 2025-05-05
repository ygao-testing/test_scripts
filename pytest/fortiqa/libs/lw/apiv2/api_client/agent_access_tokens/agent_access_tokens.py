import logging
import json
import requests


log = logging.getLogger(__name__)


class AgentAccessToken:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/AgentAccessTokens"

    def get_agent_access_token_by_id(self, agent_access_token_id: str) -> requests.Response:
        """
        Get details about an agent access token
        :param agent_access_token_id: ID of an Agent Access Token
        :return: Response
        """
        log.info(f"get_agent_access_token_by_id() for {agent_access_token_id=}")
        response = self._user_api.get(url=f"{self._api_url}/{agent_access_token_id}")
        return response

    def get_agent_access_tokens(self) -> requests.Response:
        """
        Get a list of currently enabled agent access tokens
        :return: Response
        """
        log.info("get_agent_access_tokens()")
        response = self._user_api.get(url=f"{self._api_url}")
        return response

    def create_agent_access_token(self, payload: dict) -> requests.Response:
        """
        Create a new agent access token that an agent can use to connect and send data to Lacework instance
        :param payload: payload to call the endpoint
        :return: Response
        """
        log.info("create_agent_access_token()")
        log.info(f"Create payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}", payload=payload)
        return response

    def search_agent_access_token(self, payload: dict) -> requests.Response:
        """
        Search all enabled agent access tokens in your Lacework instance
        :param payload: Search agent access tokens payload, filters and returns
        :return: Response
        """
        log.info("search_agent_access_token()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response

    # TODO update agent access token, need to use PATCH
