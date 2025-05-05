import logging
import requests


log = logging.getLogger(__name__)


class CloudActivity:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/CloudActivities"

    def get_cloud_activities(self, start_time: str, end_time: str) -> requests.Response:
        """
        Get a list of cloud activities for the current user
        :return: Response
        """
        log.info("get_cloud_activities()")
        response = self._user_api.get(url=f"{self._api_url}?startTime={start_time}&endTime={end_time}")
        return response

    def search_cloud_activities(self, payload: dict) -> requests.Response:
        """
        Search the cloud activity
        :param payload: Search cloud activity payload, timeFilter, filters and returns
        :return: Response
        """
        log.info("search_cloud_activities()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response
