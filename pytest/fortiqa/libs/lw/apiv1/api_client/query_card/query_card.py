import logging
import requests


log = logging.getLogger(__name__)


class QueryCard:

    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/card"

    def get_all_query_cards(self) -> requests.Response:
        """
        Get all query cards info
        :return: Response
        """
        log.info("get_all_query_cards()")
        response = self._user_api.get(url=f"{self._api_url}/catalog")
        return response

    def get_query_card_schema(self, card_name: str) -> requests.Response:
        """
        Get a query card's schema
        :param card_name: Name of the query card
        :return: Response
        """
        log.info(f"get_query_card_schema() for {card_name=}")
        response = self._user_api.post(url=f"{self._api_url}/schema/{card_name}")
        return response

    def exec_query_card(self, card_name: str, payload: dict) -> requests.Response:
        """
        Execute a query card
        :param card_name: Name of the query card
        :param payload: Query payload
        :return: Response
        """
        log.info(f"exec_query_card() for {card_name=}")
        response = self._user_api.post(url=f"{self._api_url}/query/{card_name}", payload=payload)
        return response

    def get_explorer_last_update(self) -> requests.Response:
        """Retrieve the latest update timestamp from the Explorer API.

        The response JSON contains:
            - 'LATEST_END_TIME': The latest end time of the ingestion period in milliseconds since epoch.
            - 'LATEST_START_TIME': The latest start time of the ingestion period in milliseconds since epoch.

        Returns:
            requests.Response: The response object from the POST request containing
                            the latest ingestion period timestamps.
        """
        log.info("Get explorer last update time")
        response = self._user_api.post(url=f"{self._api_url}/query/SecurityGraph_LatestTimestamp", payload={})
        log.info(response.json())
        return response
