import logging
import requests
import json
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import build_dynamic_payload

logger = logging.getLogger(__name__)


class InventoryAzureRoleHelper:
    """Helper class for interacting with the Lacework inventory API to retrieve Azure custom roles."""

    def __init__(self, api_v2_client: APIV2Client) -> None:
        self.inventory = InventoryV2(api_v2_client)

    def retrieve_all_custom_roles(self, time_filter: dict[str, str]) -> requests.Response:
        """
        Retrieve all custom roles in the Lacework inventory.

        Args:
            time_filter (dict[str, str]): Dictionary specifying the start and end time for filtering.

        Returns:
            requests.Response: The HTTP response from the Lacework API containing the search results.
        """
        filters = [
            {"expression": "eq", "field": "resourceConfig.type", "value": "CustomRole"},
            {"expression": "eq", "field": "resourceType", "value": "microsoft.authorization/roledefinitions"},
        ]
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for retrieving all custom roles: \n{payload}')
        return self.inventory.search_inventory(json.loads(payload))
