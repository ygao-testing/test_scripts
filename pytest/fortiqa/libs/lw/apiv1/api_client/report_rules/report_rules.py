import logging
import requests


log = logging.getLogger(__name__)


class ReportRules:

    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/notifications/rules"

    def get_all_report_rules(self) -> requests.Response:
        """
        Get all report rules info
        :return: Response
        """
        log.info("get_all_report_rules()")
        response = self._user_api.get(url=self._api_url)
        return response

    def create_report_rules(self, payload: dict) -> requests.Response:
        """
        Create report rules
        :param payload: Report rules payload
        :return: Response
        """
        log.info(f"create_report_rules() for {payload=}")
        response = self._user_api.post(url=self._api_url, payload=payload)
        return response

    def update_report_rules(self, payload: dict) -> requests.Response:
        """
        Update report rules using put method
        :param payload: Report rules payload
        :return: Response
        """
        log.info("update_report_rules()")
        response = self._user_api.patch(url=self._api_url, payload=payload)
        return response

    def delete_report_rules(self, rule_id: str) -> requests.Response:
        """
        Delete report rules
        :param rule_id: Rule ID
        :return: Response
        """
        log.info(f"delete_report_rules() for {rule_id=}")
        response = self._user_api.delete(url=f"{self._api_url}/{rule_id}")
        return response
