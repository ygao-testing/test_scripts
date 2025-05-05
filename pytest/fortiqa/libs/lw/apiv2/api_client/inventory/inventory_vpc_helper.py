import logging
import requests
import json
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import build_dynamic_payload
logger = logging.getLogger(__name__)


class InventoryVPCHelper():
    """Helper class for interacting with the Lacework inventory API to retrieve VPC-related resources.

    This class provides methods to search the Lacework inventory for VPC details using specific criteria,
    such as bucket name and account ID..., leveraging the Lacework API v2 client.

    Args:
        api_v2_client (APIV2Client): The API client instance for Lacework's inventory API v2.
    """

    def __init__(self, api_v2_client: APIV2Client) -> None:
        self.inventory = InventoryV2(api_v2_client)

    def reterive_vpc_by_vpc_id_lw(self, vpc_id: str, account_id: str, time_filter: dict[str, str]) -> requests.Response:
        """Retrieve details of a specific VPC from the Lacework inventory using the vpc id and account ID.

        This method constructs a payload with filters based on the VPC's ID, AWS account ID,
         and ec2:vpc as resourceType, and sends a request to the Lacework inventory search API to retrieve matching resources.

        Args:
            vpc_id (str): The ID of the VPC to search for.
            account_id (str): The AWS account ID associated with the VPC.
            time_filter (dict[str, str]): Dictionary specifying the start and end time for filtering

        Returns:
            requests.Response: The HTTP response from the Lacework API containing the search results.
        """
        filters = [
            {"expression": "eq", "field": "resourceConfig.VpcId", "value": vpc_id},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceType", "value": "ec2:vpc"}
        ]
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')

        api_response = self.inventory.search_inventory(json.loads(payload))
        return api_response
