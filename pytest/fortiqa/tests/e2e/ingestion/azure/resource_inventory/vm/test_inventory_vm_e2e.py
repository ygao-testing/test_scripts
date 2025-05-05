import json
import logging
import pytest
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.azure.inventory_vm_helper import InventoryVMHelper
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response, build_dynamic_payload

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_vm_helper(api_v2_client: APIV2Client) -> InventoryVMHelper:
    """
    Fixture to provide an instance of InventoryVMHelper for VM inventory operations.

    This fixture initializes an InventoryVMHelper instance, allowing test cases to interact with the
    Lacework inventory API to retrieve Azure VM-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryVMHelper: An instance of InventoryVMHelper initialized with the provided API client.
    """
    return InventoryVMHelper(api_v2_client)


@pytest.mark.order(1)
class TestResourceInventoryVME2E:
    """End-to-end test suite for Azure VM inventory operations in Lacework.

    These tests verify the functionality of the Lacework inventory API by retrieving Azure VM data,
    validating the correctness of API responses, and ensuring alignment between expected and actual VM data.
    """

    def test_inventory_find_all_vm_v2_e2e_daily_ingestion(
        self, inventory_vm_helper, azure_account, all_azure_vms, ingestion_tag, wait_for_daily_collection_completion_azure
    ):
        """Verify if all expected VMs are returned in the inventory, optionally filtered by ingestion tags.

        Given:
            - A list of Azure VMs (optionally filtered by 'ingestion_tag') and a subscription ID.
            - An instance of 'InventoryVMHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called with filters for resource type, subscription ID, and optional tags.

        Then:
            - The API should return a 200 status code.
            - The test verifies that all expected VMs are present in the API response.
            - Confirms that no unexpected VMs are found in the response.
            - Asserts there are no missing VMs by checking 'vm_id' against the expected list.

        Args:
            inventory_vm_helper: Instance of InventoryVMHelper for interacting with Lacework's VM inventory.
            azure_account: Fixture providing the Azure account details.
            all_azure_vms: A list of expected Azure VMs, sourced from the 'all_azure_vms' fixture.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tags.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        subscription_id = azure_account.subscription_id
        expected_vm_ids = {vm["vm_id"] for vm in all_azure_vms}

        filters = [
            {"expression": "eq", "field": "resourceType", "value": "microsoft.compute/virtualmachines"},
            {"expression": "eq", "field": "cloudDetails.subscriptionId", "value": subscription_id},
        ]

        if ingestion_tag:
            for key, value in ingestion_tag.items():
                filters.append({"expression": "eq", "field": f"resourceTags.{key}", "value": value})

        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for VM search: \n{payload}')

        api_response = inventory_vm_helper.inventory.search_inventory(json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Lacework response :\n{response_from_api}")
        response_from_api_data = response_from_api['data']
        response_vm_ids = {item["resourceConfig"]["vmId"] for item in response_from_api_data}

        missing_vms = expected_vm_ids - response_vm_ids
        assert not missing_vms, f"Missing VMs: {missing_vms}"

        extra_vms = response_vm_ids - expected_vm_ids
        assert not extra_vms, f"Unexpected VMs: {extra_vms}"

    def test_inventory_search_vm_by_vm_id_v2_e2e_daily_ingestion(
        self, inventory_vm_helper, azure_account, random_vm_instance, wait_for_daily_collection_completion_azure
    ):
        """Verify if a specific VM is present in the inventory by searching with the VM ID.

        Given:
            - An Azure VM with a unique VM ID.
            - An instance of 'InventoryVMHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called using the VM's unique 'vm_id' as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified VM, identified by its 'vm_id'.

        Args:
            inventory_vm_helper: Instance of InventoryVMHelper for interacting with Lacework's VM inventory.
            azure_account: Fixture providing the Azure account details.
            random_vm_instance: A randomly selected Azure VM from the 'all_azure_vms' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        subscription_id = azure_account.subscription_id
        vm_instance = random_vm_instance

        if not vm_instance:
            pytest.skip("No VM instance found")

        vm_id = vm_instance["vm_id"]
        filters = [
            {"expression": "eq", "field": "resourceConfig.vmId", "value": vm_id},
            {"expression": "eq", "field": "resourceType", "value": "microsoft.compute/virtualmachines"},
            {"expression": "eq", "field": "cloudDetails.subscriptionId", "value": subscription_id},
        ]
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for VM search by vm_id: \n{payload}')

        api_response = inventory_vm_helper.inventory.search_inventory(json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Lacework response :\n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['vmId'] == vm_id, \
                f"vmId {vm_id} is not found in {data}"

    def test_inventory_search_vm_by_resourceId_v2_e2e_daily_ingestion(
        self, inventory_vm_helper, azure_account, random_vm_instance, wait_for_daily_collection_completion_azure
    ):
        """Verify if a specific VM is present in the inventory by searching with the resourceId.

        Given:
            - An Azure VM with a 'name' corresponding to the 'resourceId' in Lacework.
            - An instance of 'InventoryVMHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called using the VM's 'resourceId' as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified VM, identified by its 'resourceId'.

        Args:
            inventory_vm_helper: Instance of InventoryVMHelper for interacting with Lacework's VM inventory.
            azure_account: Fixture providing the Azure account details.
            random_vm_instance: A randomly selected Azure VM from the 'all_azure_vms' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        subscription_id = azure_account.subscription_id
        vm_instance = random_vm_instance

        if not vm_instance:
            pytest.skip("No VM instance found")

        resource_id = vm_instance["name"]
        filters = [
            {"expression": "eq", "field": "resourceId", "value": resource_id},
            {"expression": "eq", "field": "resourceType", "value": "microsoft.compute/virtualmachines"},
            {"expression": "eq", "field": "cloudDetails.subscriptionId", "value": subscription_id},
        ]
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for VM search by resourceId: \n{payload}')

        api_response = inventory_vm_helper.inventory.search_inventory(json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceId'] == resource_id, \
                f"resourceId {resource_id} is not found in {data}"

    @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/RAIN-94198')
    def test_inventory_search_vm_by_urn_v2_e2e_daily_ingestion(
        self, inventory_vm_helper, azure_account, random_vm_instance, wait_for_daily_collection_completion_azure
    ):
        """Verify if a specific VM is present in the inventory by searching with the urn.

        Given:
            - An Azure VM with an 'id' corresponding to the 'urn' in Lacework.
            - An instance of 'InventoryVMHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called using the VM's 'urn' as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified VM, identified by its 'urn'.

        Args:
            inventory_vm_helper: Instance of InventoryVMHelper for interacting with Lacework's VM inventory.
            azure_account: Fixture providing the Azure account details.
            random_vm_instance: A randomly selected Azure VM from the 'all_azure_vms' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        subscription_id = azure_account.subscription_id
        vm_instance = random_vm_instance

        if not vm_instance:
            pytest.skip("No VM instance found")

        urn = vm_instance["id"]
        filters = [
            {"expression": "eq", "field": "urn", "value": urn},
            {"expression": "eq", "field": "resourceType", "value": "microsoft.compute/virtualmachines"},
            {"expression": "eq", "field": "cloudDetails.subscriptionId", "value": subscription_id},
        ]
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for VM search by urn: \n{payload}')

        api_response = inventory_vm_helper.inventory.search_inventory(json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['urn'] == urn, \
                f"urn {urn} is not found in {data}"
