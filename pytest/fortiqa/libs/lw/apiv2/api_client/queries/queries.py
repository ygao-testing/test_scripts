import logging
from dataclasses import asdict
from typing import Any
from fortiqa.libs.lw.apiv2.payloads import QueryPayload

import requests

log = logging.getLogger(__name__)


class Queries:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/Queries"

    def create_queries(self, query_text: str, query_id: str) -> requests.Response:
        """
        Create a Lacework Query Language (LQL) query by specifying parameters in the request body
        :param query_text: When sending a request, provide a human-readable text syntax for specifying selection, filtering, and manipulation of data.
        :param query_id: Identifier of the query that executes while running the policy.
        :return: Response
        """
        log.info("create_queries()")
        query_data = QueryPayload(queryText=query_text, queryId=query_id)
        response = self._user_api.post(url=self._api_url, payload=asdict(query_data))
        return response

    def list_queries(self) -> requests.Response:
        """
        List all registered LQL queries in your Lacework instance
        :return: Response
        """
        log.info("list_queries()")
        response = self._user_api.get(url=self._api_url)
        return response

    def execute_queries(self, query_text: str, start_time: str, end_time: str, limit: int | None = None) -> requests.Response:
        """
        Execute a Lacework Query Language (LQL) query to execute a query
        :param query_text: When sending a request, provide a human-readable text syntax for specifying selection, filtering, and manipulation of data.
        :param start_time: Start time
        :param end_time: End time
        :param limit: Number of results expected to return
        :return: Response
        """
        log.info("execute_queries()")
        payload = {
            "query": {
                "queryText": query_text
            },
            "arguments": [
                {
                    "name": "StartTimeRange",
                    "value": start_time
                },
                {
                    "name": "EndTimeRange",
                    "value": end_time
                }
            ]
        }
        if limit:
            payload["options"] = {
                "limit": limit
            }
        response = self._user_api.post(url=f"{self._api_url}/execute", payload=payload)
        return response

    def execute_queries_by_id(self, query_id: str, start_time: str, end_time: str, limit: int | None = None) -> requests.Response:
        """
        Execute a Lacework Query Language (LQL) query to execute a query by query_id
        :param query_id: ID of the query
        :param start_time: Start time
        :param end_time: End time
        :param limit: Number of results expected to return
        :return: Response
        """
        log.info("execute_queries_by_id()")
        payload: dict[str, Any] = {
            "arguments": [
                {
                    "name": "StartTimeRange",
                    "value": start_time
                },
                {
                    "name": "EndTimeRange",
                    "value": end_time
                }
            ]
        }
        if limit:
            payload["options"] = {
                "limit": limit
            }
        response = self._user_api.post(url=f"{self._api_url}/{query_id}/execute", payload=payload)
        return response

    def validate_queries(self, query_text: str) -> requests.Response:
        """
        Validate an LQL query by specifying parameters in the request body
        :param query_text: When sending a request, provide a human-readable text syntax for specifying selection, filtering, and manipulation of data.
        :return: Response
        """
        log.info("validate_queries()")
        payload = {
            "queryText": query_text
        }
        response = self._user_api.post(url=f"{self._api_url}/validate", payload=payload)
        return response

    def get_query_details(self, query_id: str) -> requests.Response:
        """
        Get details about a single LQL query by query_id
        :param query_id: ID of the query
        :return: Response
        """
        log.info("execute_queries_by_id()")
        payload = {
            "queryId": query_id
        }
        response = self._user_api.get(url=f"{self._api_url}/{query_id}", payload=payload)
        return response

    def delete_queries(self, query_id: str) -> requests.Response:
        """
        Delete a Lacework Query Language (LQL) query by query_id
        :param query_id: ID of the query
        :return: Response
        """
        log.info("delete_queries()")
        payload = {
            "queryId": query_id
        }
        response = self._user_api.delete(url=f"{self._api_url}/{query_id}", payload=payload)
        return response

    # TODO This one use PATCH
    # def update_queries(self, query_text: str, query_id: str) -> requests.Response:
    #     """
    #     Update an existing LQL query
    #     :param query_text: When sending a request, provide a human-readable text syntax for specifying selection, filtering, and manipulation of data.
    #     :param query_id: ID of the query
    #     :return: Response
    #     """
    #     log.info("update_queries()")
    #     payload = {
    #         "queryText": query_text
    #     }
    #     response = self._user_api.post(url=f"{self._api_url}/{query_id}", payload=payload)
    #     return response
