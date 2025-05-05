import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_nat_gateway_helper import InventoryNatGatewayHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_nat_gateway_helper(api_v2_client: APIV2Client) -> InventoryNatGatewayHelper:
    """Fixture to provide an instance of InventoryNatGatewayHelper for NAT Gateway inventory operations.

    This fixture initializes an InventoryNatGatewayHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving NAT Gateway-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryNatGatewayHelper: An instance of InventoryNatGatewayHelper initialized with the provided API client.
    """
    return InventoryNatGatewayHelper(api_v2_client)


class TestResourceInventoryNatGatewayE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_nat_gateway_by_id_v2_e2e_daily_ingestion(self, inventory_nat_gateway_helper, random_nat_gateway, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the NAT Gateway is present in the Lacework inventory by searching with the NAT Gateway ID and account ID.

        Given:
         - A NAT Gateway with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the NAT Gateway's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified NAT Gateway, identified by its ID and account ID.

        Args:
         inventory_nat_gateway_helper: Instance of InventoryNatGatewayHelper for interacting with Lacework's NAT Gateway inventory.
         random_nat_gateway: A 'NatGateway' object representing a randomly selected NAT Gateway.
         aws_region: AWS region where the NAT Gateway is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        nat_gateway = random_nat_gateway
        if not nat_gateway:
            pytest.skip(f"There is no NAT Gateway in {aws_region}")

        api_response = inventory_nat_gateway_helper.retrieve_nat_gateway_by_id(
            nat_gateway.nat_gateway_id, nat_gateway.account_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['NatGatewayId'] == nat_gateway.nat_gateway_id, \
                f"NAT Gateway {nat_gateway.nat_gateway_id} is not found in {data}"
