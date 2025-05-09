import logging
import json
import requests


log = logging.getLogger(__name__)


class NewAgentDashboard:
    """New Agent Dashboard API V1"""

    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/card/query/AGENT_FLEET_InventoryTable"

    def get_agent_inventory(self, payload: dict) -> requests.Response:
        """
        Get agents inventory table according to payload

        :param payload: Query payload
        :return: Response
        """
        log.info("get_agent_inventory()")
        log.debug(f"Payload: {json.dumps(payload, indent=2)}")
        response = self._user_api.post(url=self._api_url, payload=payload)
        return response
