import json
import logging
import pytest
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.azure.inventory_role_helper import InventoryAzureRoleHelper
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response, build_dynamic_payload

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_role_helper(api_v2_client: APIV2Client) -> InventoryAzureRoleHelper:
    """
    Fixture to provide an instance of InventoryAzureRoleHelper for role inventory operations.

    This fixture initializes an InventoryAzureRoleHelper instance, allowing test cases to interact with the
    Lacework inventory API to retrieve Azure custom role-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryAzureRoleHelper: An instance of InventoryAzureRoleHelper initialized with the provided API client.
    """
    return InventoryAzureRoleHelper(api_v2_client)


@pytest.mark.order(2)
class TestResourceInventoryRoleE2E:
    """End-to-end test suite for Azure role inventory operations in Lacework.

    These tests verify the functionality of the Lacework inventory API by retrieving Azure role data,
    validating the correctness of API responses, and ensuring alignment between expected and actual role data.
    """

    def test_inventory_find_all_roles_e2e_daily_ingestion(self, inventory_role_helper, all_azure_roles, wait_for_daily_collection_completion_azure):
        """Verify if all expected Azure custom roles are returned in the inventory.

        Given:
            - A list of Azure custom roles from the 'all_azure_roles' fixture.
            - An instance of 'InventoryAzureRoleHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called with filters for resource type and role type.

        Then:
            - The API should return a 200 status code.
            - The test verifies that all expected custom roles are present in the API response.
            - Asserts there are no missing custom roles by matching 'resourceId' from the Lacework response with 'name' from the Azure API response.

        Note:
            - The 'resourceId' field in the Lacework response corresponds to the 'name' field in the Azure API response.

        Args:
            inventory_role_helper: Instance of InventoryAzureRoleHelper for interacting with Lacework's role inventory.
            azure_account: Fixture providing the Azure account details.
            all_azure_roles: A list of expected Azure custom roles, sourced from the 'all_azure_roles' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """

        # Extract expected role resource IDs from the Azure response
        expected_role_ids = {role["name"] for role in all_azure_roles}

        # Define filters for Lacework's inventory API
        filters = [
            {"expression": "eq", "field": "resourceConfig.type", "value": "CustomRole"},
            {"expression": "eq", "field": "resourceType",
                "value": "microsoft.authorization/roledefinitions"},
        ]

        # Build the payload for the API request
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, "Azure")
        logger.info(f"Payload for role search: \n{payload}")

        # Make the API call to Lacework
        api_response = inventory_role_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"

        # Parse the API response
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Lacework response :\n{response_from_api}")
        response_from_api_data = response_from_api["data"]

        # Extract resource IDs from Lacework response
        response_role_ids = {item["resourceId"]
                             for item in response_from_api_data}

        # Check for missing roles (roles in Azure but not in Lacework response)
        missing_roles = expected_role_ids - response_role_ids
        assert not missing_roles, f"Missing roles: {missing_roles}"

    def test_inventory_search_role_by_resourceId_v2_e2e_daily_ingestion(
        self, inventory_role_helper, random_role_instance, wait_for_daily_collection_completion_azure
    ):
        """Verify if a specific Azure custom role is present in the inventory by searching with the resourceId.

        Given:
            - An Azure custom role with a 'name' corresponding to the 'resourceId' in Lacework.
            - An instance of 'InventoryAzureRoleHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called using the role's 'resourceId' as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified custom role, identified by its 'resourceId'.

        Args:
            inventory_role_helper: Instance of InventoryAzureRoleHelper for interacting with Lacework's role inventory.
            random_role_instance: A randomly selected Azure custom role from the 'all_azure_roles' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        role_instance = random_role_instance

        if not role_instance:
            pytest.skip("No role instance found")

        resource_id = role_instance["name"]
        filters = [
            {"expression": "eq", "field": "resourceId", "value": resource_id},
        ]
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for role search by resourceId: \n{payload}')

        api_response = inventory_role_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceId'] == resource_id, \
                f"resourceId {resource_id} is not found in {data}"

    @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/RAIN-94198 & https://lacework.atlassian.net/browse/RAIN-94252')
    def test_inventory_search_role_by_urn_v2_e2e_daily_ingestion(
        self, inventory_role_helper, random_role_instance, wait_for_daily_collection_completion_azure
    ):
        """Verify if a specific Azure custom role is present in the inventory by searching with the urn.

        Given:
            - An Azure custom role with an 'id' corresponding to the 'urn' in Lacework.
            - An instance of 'InventoryAzureRoleHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called using the role's 'urn' as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified custom role, identified by its 'urn'.

        Args:
            inventory_role_helper: Instance of InventoryAzureRoleHelper for interacting with Lacework's role inventory.
            random_role_instance: A randomly selected Azure custom role from the 'all_azure_roles' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        role_instance = random_role_instance

        if not role_instance:
            pytest.skip("No role instance found")

        urn = role_instance["id"]
        filters = [
            {"expression": "eq", "field": "urn", "value": urn},
        ]
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for role search by urn: \n{payload}')

        api_response = inventory_role_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['urn'] == urn, \
                f"urn {urn} is not found in {data}"

    def test_inventory_search_role_by_role_name_v2_e2e_daily_ingestion(
        self, inventory_role_helper, random_role_instance, wait_for_daily_collection_completion_azure
    ):
        """Verify if a specific Azure custom role is present in the inventory by searching with the roleName.

        Given:
            - An Azure custom role with a 'role_name' corresponding to the 'resourceConfig.roleName' in Lacework.
            - An instance of 'InventoryAzureRoleHelper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.

        When:
            - The inventory search API v2 is called using the role's 'roleName' as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified custom role, identified by its 'roleName'.

        Args:
            inventory_role_helper: Instance of InventoryAzureRoleHelper for interacting with Lacework's role inventory.
            random_role_instance: A randomly selected Azure custom role from the 'all_azure_roles' fixture.
            wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        role_instance = random_role_instance

        if not role_instance:
            pytest.skip("No role instance found")

        role_name = role_instance["role_name"]
        filters = [
            {"expression": "eq", "field": "resourceConfig.roleName", "value": role_name},
        ]
        time_filter = wait_for_daily_collection_completion_azure
        payload = build_dynamic_payload(time_filter, filters, 'Azure')
        logger.info(f'Payload for role search by roleName: \n{payload}')

        api_response = inventory_role_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['roleName'] == role_name, \
                f"roleName {role_name} is not found in {data}"
