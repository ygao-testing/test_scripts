import time
import logging
import requests

from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv2.api_client.lacework_resource import LaceworkResource

logger = logging.getLogger(__name__)

class Alert(LaceworkResource):
    """
    Class to interact with Alerts in Lacework API V1.

    This class inherits from LaceworkResource and initializes specific fields for Alerts.
    """

    def __init__(self, user_api) -> None:
        """
        Initialize the Alerts with the user API and optional resource payload.

        :param user_api: The user API instance to interact with the Lacework API.
        :param resource_payload: Optional dictionary containing the alert profile payload.
        """
        super().__init__(user_api)
        self._api_url = f"{user_api.url}/alerts"

    def close_alert(self, alert_id: str) -> requests.Response:
        """
        Close an alert by alert ID.

        Args:
            alert_id: The alert ID to close.

        Returns:
            requests.Response: The response object from the API call.
        """
        url = f"{self._api_url}/{alert_id}"
        resp = self._user_api.patch(
            url, payload={
                "status":"Closed","primaryIntgGuid": None,
                "feedbackCode":22,"message":{"format":"Markdown:1.0","value":"Auto-Test"}})
        assert resp.status_code == 200, f"Expected 200 status code but got {
                                        resp.status_code}."
        assert "errors" not in resp.json(), f"Expected no errors in response, but got {
            resp.json()['errors'][0]['message']}."
        
        return resp
    
    def change_alert_status(self, alert_id: str, status) -> requests.Response:
        url = f"{self._api_url}/{alert_id}"
        resp = self._user_api.patch(
            url, payload={
                "status":status,"primaryIntgGuid": None,
                "feedbackCode":22,"message":{"format":"Markdown:1.0","value":"Auto-Test"}})
        if resp.status_code == 200:
            return True
        else:
            return False

    def wait_until_alert_is_generated(self, payload=None, frequent=15, timeout=900) -> requests.Response:
        """
        Wait until alert is generated in Lacework.
        
        Args:
            payload: Payload to query the alert.
            frequent: Heartbeat to run next query, default: 15, seconds
            timeout: Waiting time for alert generation, default: 900s
            
        Raises:
            TimeoutError: If alert is not generated in 900 seconds.
        
        Returns:
            requests.Response: The response object from the API call.
        """

        query_card_api = QueryCard(self._user_api)
        alert_found = False
        start_time = time.time()
        while True:
            elapsed_time = time.time() - start_time
            query_card_response = query_card_api.exec_query_card(
                card_name='Card113_AlertInbox', payload=payload)
            if query_card_response.status_code == 200 and query_card_response.json()['data']:
                alert_found = True
                break
            if elapsed_time > timeout:
                break
            time.sleep(frequent)
        
        if not alert_found:
            raise TimeoutError(f'Alert not found in {timeout} seconds.')
            
        return query_card_response


    def get_alert(self, payload=None) -> requests.Response:

        query_card_api = QueryCard(self._user_api)
        alert_id = None

        query_card_response = query_card_api.exec_query_card(card_name='Card113_AlertInbox', payload=payload)

        if query_card_response.status_code == 200 and query_card_response.json()['data']:
            alert_id = query_card_response.json()['data'][0]['alertId']

        return alert_id