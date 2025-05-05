import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_ec2_snapshot_helper import InventoryEc2SnapshotHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_ec2_snapshot_helper(api_v2_client: APIV2Client) -> InventoryEc2SnapshotHelper:
    """Fixture to provide an instance of InventoryEc2SnapshotHelper for EC2 Snapshot inventory operations.

    This fixture initializes an InventoryEc2SnapshotHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving EC2 Snapshot-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryEc2SnapshotHelper: An instance of InventoryEc2SnapshotHelper initialized with the provided API client.
    """
    return InventoryEc2SnapshotHelper(api_v2_client)


class TestResourceInventoryEc2SnapshotE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_snapshot_by_id_v2_e2e_daily_ingestion(self, inventory_ec2_snapshot_helper, random_snapshot, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the EC2 Snapshot is present in the Lacework inventory by searching with the Snapshot ID and account ID.

        Given:
         - An EC2 Snapshot with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the Snapshot's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified Snapshot, identified by its ID and account ID.

        Args:
         inventory_ec2_snapshot_helper: Instance of InventoryEc2SnapshotHelper for interacting with Lacework's EC2 Snapshot inventory.
         random_snapshot: A 'Snapshot' object representing a randomly selected EC2 Snapshot.
         aws_region: AWS region where the EC2 Snapshot is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        snapshot = random_snapshot
        if not snapshot:
            pytest.skip(f"There is no EC2 Snapshot in {aws_region}")

        api_response = inventory_ec2_snapshot_helper.retrieve_snapshot_by_id(
            snapshot.snapshot_id, snapshot.account_id, time_filter)
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['SnapshotId'] == snapshot.snapshot_id, \
                f"EC2 Snapshot {snapshot.snapshot_id} is not found in {data}"
