import logging
import json
import requests


log = logging.getLogger(__name__)


class VulnerabilityObservation:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/VulnerabilityObservations"

    def search_host_vulnerability_observations(self, payload: dict) -> requests.Response:
        """
        Search for vulnerability observations that occur in hosts, including risk scores, observation statuses, and detailed statistics.
        :param payload: Payload to call the endpoint
        :return: Response
        """
        log.debug("serach_host_vulnerability_observations()")
        log.debug(f"Payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/Hosts/search", payload=payload)
        return response

    def search_image_vulnerability_observations(self, payload: dict) -> requests.Response:
        """
        Search for vulnerability observations that occur in images (containers), including risk scores, observation statuses, and detailed statistics.
        :param payload: payload to call the endpoint
        :return: Response
        """
        log.debug("serach_image_vulnerability_observations()")
        log.debug(f"Payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/Images/search", payload=payload)
        return response
