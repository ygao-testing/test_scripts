import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_internet_gateway_helper import InventoryInternetGatewayHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_internet_gateway_helper(api_v2_client: APIV2Client) -> InventoryInternetGatewayHelper:
    """Fixture to provide an instance of InventoryInternetGatewayHelper for Internet Gateway inventory operations.

    This fixture initializes an InventoryInternetGatewayHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving Internet Gateway-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryInternetGatewayHelper: An instance of InventoryInternetGatewayHelper initialized with the provided API client.
    """
    return InventoryInternetGatewayHelper(api_v2_client)


class TestResourceInventoryInternetGatewayE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_internet_gateway_by_id_v2_e2e_daily_ingestion(self, inventory_internet_gateway_helper, random_internet_gateway, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the Internet Gateway is present in the Lacework inventory by searching with the Internet Gateway ID and account ID.

        Given:
         - An Internet Gateway with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the Internet Gateway's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified Internet Gateway, identified by its ID and account ID.

        Args:
         inventory_internet_gateway_helper: Instance of InventoryInternetGatewayHelper for interacting with Lacework's Internet Gateway inventory.
         random_internet_gateway: An 'InternetGateway' object representing a randomly selected Internet Gateway.
        aws_region: AWS region where the Internet Gateway is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        internet_gateway = random_internet_gateway
        if not internet_gateway:
            pytest.skip(f"There is no Internet Gateway in {aws_region}")

        api_response = inventory_internet_gateway_helper.retrieve_internet_gateway_by_id(
            internet_gateway.internet_gateway_id, internet_gateway.owner_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['InternetGatewayId'] == internet_gateway.internet_gateway_id, \
                f"Internet Gateway {internet_gateway.internet_gateway_id} is not found in {data}"
