import logging
import requests
import json
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import build_dynamic_payload

logger = logging.getLogger(__name__)


class InventoryEc2SnapshotHelper:
    """Helper class for interacting with the Lacework inventory API to retrieve EC2 Snapshot-related resources.

    This class provides methods to search the Lacework inventory for EC2 Snapshot details using specific criteria,
    such as snapshot ID and account ID, leveraging the Lacework API v2 client.

    Args:
        api_v2_client (APIV2Client): The API client instance for Lacework's inventory API v2.
    """

    def __init__(self, api_v2_client: APIV2Client) -> None:
        self.inventory = InventoryV2(api_v2_client)

    def retrieve_snapshot_by_id(self, snapshot_id: str, account_id: str, time_filter: dict[str, str]) -> requests.Response:
        """Retrieve details of a specific EC2 Snapshot from the Lacework inventory using the Snapshot ID and account ID.

        This method constructs a payload with filters based on the Snapshot's ID, AWS account ID,
        and ec2:snapshot as resourceType, and sends a request to the Lacework inventory search API to retrieve matching resources.

        Args:
            snapshot_id (str): The ID of the EC2 Snapshot to search for.
            account_id (str): The AWS account ID associated with the EC2 Snapshot.
            time_filter (dict[str, str]): Dictionary specifying the start and end time for filtering.

        Returns:
            requests.Response: The HTTP response from the Lacework API containing the search results.
        """
        filters = [
            {"expression": "eq", "field": "resourceConfig.SnapshotId", "value": snapshot_id},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceType", "value": "ec2:snapshot"}
        ]
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'Payload for EC2 Snapshot search: \n{payload}')

        api_response = self.inventory.search_inventory(json.loads(payload))
        return api_response
