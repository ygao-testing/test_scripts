import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_route_table_helper import InventoryRouteTableHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_route_table_helper(api_v2_client: APIV2Client) -> InventoryRouteTableHelper:
    """Fixture to provide an instance of InventoryRouteTableHelper for Route Table inventory operations.

    This fixture initializes an InventoryRouteTableHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving Route Table-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryRouteTableHelper: An instance of InventoryRouteTableHelper initialized with the provided API client.
    """
    return InventoryRouteTableHelper(api_v2_client)


class TestResourceInventoryRouteTableE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_route_table_by_id_v2_e2e_daily_ingestion(self, inventory_route_table_helper, random_route_table, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the Route Table is present in the Lacework inventory by searching with the Route Table ID and account ID.

        Given:
         - A Route Table with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the Route Table's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified Route Table, identified by its ID and account ID.

        Args:
         inventory_route_table_helper: Instance of InventoryRouteTableHelper for interacting with Lacework's Route Table inventory.
         random_route_table: A 'RouteTable' object representing a randomly selected Route Table.
         aws_region: AWS region where the Route Table is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        route_table = random_route_table
        if not route_table:
            pytest.skip(f"There is no Route Table in {aws_region}")

        api_response = inventory_route_table_helper.retrieve_route_table_by_id(
            route_table.route_table_id, route_table.owner_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['RouteTableId'] == route_table.route_table_id, \
                f"Route Table {route_table.route_table_id} is not found in {data}"
