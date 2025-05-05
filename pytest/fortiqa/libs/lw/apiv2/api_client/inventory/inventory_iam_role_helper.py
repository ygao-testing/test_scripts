import logging
import requests
import json
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import build_dynamic_payload

logger = logging.getLogger(__name__)


class InventoryIAMRoleHelper:
    """Helper class for interacting with the Lacework inventory API to retrieve IAM Role-related resources.

    This class provides methods to search the Lacework inventory for IAM Role details using specific criteria,
    such as RoleId and account ID, leveraging the Lacework API v2 client.

    Args:
        api_v2_client (APIV2Client): The API client instance for Lacework's inventory API v2.
    """

    def __init__(self, api_v2_client: APIV2Client) -> None:
        self.inventory = InventoryV2(api_v2_client)

    def retrieve_role_by_id(self, role_id: str, account_id: str, time_filter: dict[str, str]) -> requests.Response:
        """Retrieve details of a specific IAM Role from the Lacework inventory using the RoleId and account ID.

        This method constructs a payload with filters based on the Role's ID, AWS account ID,
        and iam:role as resourceType, and sends a request to the Lacework inventory search API to retrieve matching resources.

        Args:
            role_id (str): The ID of the IAM Role to search for.
            account_id (str): The AWS account ID associated with the IAM Role.
            time_filter (dict[str, str]): Dictionary specifying the start and end time for filtering.

        Returns:
            requests.Response: The HTTP response from the Lacework API containing the search results.
        """
        filters = [
            {"expression": "eq", "field": "resourceConfig.RoleId", "value": role_id},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceType", "value": "iam:role"}
        ]
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'Payload for IAM Role search: \n{payload}')

        api_response = self.inventory.search_inventory(json.loads(payload))
        return api_response
