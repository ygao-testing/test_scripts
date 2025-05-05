import logging
import json
import requests


log = logging.getLogger(__name__)


class Vulnerability:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/Vulnerabilities"

    def scan_software_packages(self, payload: dict) -> requests.Response:
        """
        Request an on-demand vulnerability assessment of your software packages to determine if the packages contain any common vulnerabilities and exposures. The response for detected CVEs includes CVE details.
        :param payload: payload to call the endpoint
        :return: Response
        """
        log.info("scan_software_packages()")
        log.info(f"scan payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/SoftwarePackages/scan", payload=payload)
        return response

    def track_container_scan_status(self, request_id) -> requests.Response:
        """
        Track the progress and return data about an on-demand vulnerability scan that was started
        :param request_id: Assessment Request ID
        :return: Response
        """
        log.info(f"track_container_scan_status() for {request_id=}")
        response = self._user_api.get(url=f"{self._api_url}/Containers/scan/{request_id}")
        return response

    def scan_container_vulnerabilities(self, payload: dict) -> requests.Response:
        """
        Request that Lacework scans (evaluates) for vulnerabilities in the specified container image.
        :param payload: payload to call the endpoint
        :return: Response
        """
        log.info("scan_container_vulnerabilities()")
        log.info(f"scan payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/Containers/scan", payload=payload)
        return response

    def search_container_vulnerabilities(self, payload: dict) -> requests.Response:
        """
        Search the scan (assessment), including the risk score and scan status, the vulnerabilities found in the scan, and statistics for those vulnerabilities
        :param payload: Search container vulnerabilities payload, timeFilter, filters and returns
        :return: Response
        """
        log.info("search_container_vulnerabilities()")
        response = self._user_api.post(url=f"{self._api_url}/Containers/search", payload=payload)
        return response

    def search_host_vulnerabilities(self, payload: dict) -> requests.Response:
        """
        Search the scan (assessment), including the risk score and scan status, vulnerabilities found in the scan, and statistics about those vulnerabilities
        :param payload: Search host vulnerabilities payload, timeFilter, filters and returns
        :return: Response
        """
        log.info("search_host_vulnerabilities()")
        response = self._user_api.post(url=f"{self._api_url}//search", payload=payload)
        return response
