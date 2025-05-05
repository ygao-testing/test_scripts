import logging
import requests


log = logging.getLogger(__name__)


class Alert:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/Alerts"

    def get_alerts(self, start_time: str, end_time: str) -> requests.Response:
        """
        Get a list of alerts for the current user
        :return: Response
        """
        log.info("get_alerts()")
        response = self._user_api.get(url=f"{self._api_url}?startTime={start_time}&endTime={end_time}")
        return response

    def search_alerts(self, payload: dict) -> requests.Response:
        """
        Search alerts
        :param payload: Search alert payload, filters and returns
        :return: Response
        """
        log.info("search_alert()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response

    def get_alert_details(self, alertId: str) -> requests.Response:
        """
        Get details of an alert
        :param alertId: Alert ID
        """
        log.info(f"get_alert_details() for {alertId=}")
        response = self._user_api.get(url=f"{self._api_url}/{alertId}")
        return response

    def get_alert_entities(self, alertId: str) -> requests.Response:
        """
        List all entities associated with a given alert ID for which additional context is available
        :param alertId: Alert ID
        """
        log.info(f"get_alert_entities() for {alertId=}")
        response = self._user_api.get(url=f"{self._api_url}/Entities/{alertId}")
        return response

    def get_alert_entities_details(self, alertId: str) -> requests.Response:
        """
        Get details about an entity associated with a given alert ID
        :param alertId: Alert ID
        """
        log.info(f"get_alert_entities_details() for {alertId=}")
        response = self._user_api.get(url=f"{self._api_url}/EntityDetails/{alertId}")
        return response

    def post_comment(self, comment: str, alertId: str) -> requests.Response:
        """
        Post a user comment on an alert's timeline
        :param comment: Comment
        :param alertId: Alert ID
        :return: Response
        """
        log.info(f"post_comment() for {alertId=}")
        payload = dict(comment=comment)
        response = self._user_api.post(url=f"{self._api_url}/{alertId}/comment", payload=payload)
        return response

    def close_alert(self, alertId: str) -> requests.Response:
        """
        Change the status of an alert to closed
        :param alertId: Alert ID
        """
        log.info(f"close_alert() for {alertId=}")
        response = self._user_api.post(url=f"{self._api_url}/{alertId}/close")
        return response
