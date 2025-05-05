import logging
import requests


log = logging.getLogger(__name__)


class AuditLog:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/AuditLogs"

    def get_audit_logs(self, start_time: str, end_time: str) -> requests.Response:
        """
        Get a list of audit logs for the current user
        :return: Response
        """
        log.info("get_audit_logs()")
        response = self._user_api.get(url=f"{self._api_url}?startTime={start_time}&endTime={end_time}")
        return response

    def search_audit_logs(self, payload: dict) -> requests.Response:
        """
        Search the audit logs
        :param payload: Search audit log payload, timeFilter, filters and returns
        :return: Response
        """
        log.info("search_audit_logs()")
        response = self._user_api.post(url=f"{self._api_url}/search", payload=payload)
        return response
