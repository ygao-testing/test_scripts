import logging
import requests
import json
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import build_dynamic_payload

logger = logging.getLogger(__name__)


class InventoryVMHelper:
    """Helper class for interacting with the Lacework inventory API to retrieve Azure VM-related resources."""
    def __init__(self, api_v2_client: APIV2Client) -> None:
        self.inventory = InventoryV2(api_v2_client)

    def retrieve_vm_by_vm_id_from_lw(self, vm_id: str, subscription_id: str, time_filter: dict[str, str]) -> requests.Response:
        """Retrieve details of a specific VM from the Lacework inventory using the VM ID and subscription ID.

        Args:
            vm_id (str): The unique VM ID to search for.
            subscription_id (str): The Azure subscription ID associated with the VM.
            time_filter (dict[str, str]): Dictionary specifying the start and end time for filtering.

        Returns:
            requests.Response: The HTTP response from the Lacework API containing the search results.
        """
        filters = [
            {"expression": "eq", "field": "resourceConfig.vmId", "value": vm_id},
            {"expression": "eq", "field": "cloudDetails.subscriptionId",
                "value": subscription_id},
            {"expression": "eq", "field": "resourceType",
                "value": "microsoft.compute/virtualmachines"}
        ]
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for VM search by vm_id: \n{payload}')
        return self.inventory.search_inventory(json.loads(payload))

    def retrieve_all_vms_by_subscription(self, subscription_id: str, time_filter: dict[str, str], ingestion_tag: dict[str, str] | None = None) -> requests.Response:
        """Retrieve all VMs in a subscription, optionally filtered by ingestion tags.

        Args:
            subscription_id (str): The Azure subscription ID.
            time_filter (dict[str, str]): Dictionary specifying the start and end time for filtering.
            ingestion_tag (dict[str, str], optional): Tags for filtering VMs. Defaults to None.

        Returns:
            requests.Response: The HTTP response from the Lacework API containing the search results.
        """
        filters = [
            {"expression": "eq", "field": "resourceType",
                "value": "microsoft.compute/virtualmachines"},
            {"expression": "eq", "field": "cloudDetails.subscriptionId",
                "value": subscription_id},
        ]

        if ingestion_tag:
            for key, value in ingestion_tag.items():
                filters.append(
                    {"expression": "eq", "field": f"resourceTags.{key}", "value": value})

        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for all VMs search: \n{payload}')
        return self.inventory.search_inventory(json.loads(payload))
