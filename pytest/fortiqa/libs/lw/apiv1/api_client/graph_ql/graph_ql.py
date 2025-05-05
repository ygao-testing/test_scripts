import logging
import requests
import json


logger = logging.getLogger(__name__)


class GraphQL:

    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/graphql"

    def exec_query(self, payload: dict) -> requests.Response:
        """
        Execute a query card
        :param card_name: Name of the query card
        :param payload: Query payload
        :return: Response
        """
        logger.info("exec_query()")
        logger.info(f"Payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=self._api_url, payload=payload)
        return response
