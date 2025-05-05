import json
import logging
import requests

from fortiqa.libs.lw.apiv2.api_client.queries.queries import Queries


logger = logging.getLogger(__name__)


class QueryHelper:
    def __init__(self, user_api):
        self.query_api = Queries(user_api)

    def get_all_queries(self) -> requests.Response:
        """Helper function to GET all queries"""
        logger.info("get_all_queries()")
        all_queries = self.query_api.list_queries()
        return all_queries

    def create_query(self, query_text: str, query_id: str) -> requests.Response:
        """
        Helper function to create a query
        :param query_test: When sending a request, provide a human-readable text syntax for specifying selection, filtering, and manipulation of data.
        :param query_id: ID of the query
        :return: Response
        """
        logger.info("create_query()")
        response = self.query_api.create_queries(query_text=query_text,
                                                 query_id=query_id)
        logger.info(json.dumps(response.text, indent=2))
        return response

    def execute_query_by_id(self, query_id: str, start_time_range: str, end_time_range: str) -> requests.Response:
        """
        Helper function to execute an existing query by queryId
        :param query_id: ID of the existing query
        :param start_time_range: Start time
        :param end_time_range: End time
        :return: Response
        """
        logger.info("execute_query_by_id()")
        response = self.query_api.execute_queries_by_id(query_id=query_id,
                                                        start_time=start_time_range,
                                                        end_time=end_time_range)
        logger.info(json.dumps(response.text, indent=2))
        return response

    def delete_query_by_id(self, query_id: str) -> None:
        """
        Helper function to delete an existing query by queryId
        :param query_id: ID of the existing query
        :return: Response
        """
        logger.info("delete_query_by_id()")
        self.query_api.delete_queries(query_id=query_id)
