import json
import logging
import pytest
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response, build_dynamic_payload

logger = logging.getLogger(__name__)


class TestResourceInventory:

    s3_bucket = ["lacework-ct-bucket-e2acf592"]

    @pytest.mark.parametrize("s3_bucket_name", s3_bucket)
    def test_inventory_s3_bucket_configured_for_cloud_trail_v2(self, api_v2_client, time_filter, s3_bucket_name):
        """Verify if the configured S3 bucket for CloudTrail is in the resource inventory using API V2.

        Given:  An S3 bucket name and a time filter,
        When:  The inventory search API is called with the S3 bucket, region, time filter and  filters
        Then:  The API should return a 200 status code, and the S3 bucket should be present in the inventory data.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API V2.
            time_filter: Time filter for querying the inventory.
            s3_bucket_name: The name of the S3 bucket.
        """
        filters = [
            {"expression": "eq", "field": "resourceRegion", "value": "us-west-2"},
            {"expression": "eq", "field": "resourceConfig.S3BucketName", "value": s3_bucket_name}
        ]
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_instance = InventoryV2(api_v2_client)
        api_response = api_instance.search_inventory(json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        try:
            response_from_api = check_and_return_json_from_response(api_response)
        except ValueError:
            pytest.fail("API response is not in valid JSON format")
        try:
            response_from_api_data = response_from_api['data']
            found = False
            for data in response_from_api_data:
                if data['resourceConfig']['S3BucketName'] == s3_bucket_name:
                    found = True
                    break
            assert found, f's3 bucket "lacework-ct-bucket-13c8fd71" is not found in {response_from_api_data}'
        except KeyError as e:
            logger.info(f' response body: \n {response_from_api_data}')
            pytest.fail(f'Faild  to find key {e} in response')

    account_id = ["183631341284"]

    @pytest.mark.parametrize("account_id", account_id)
    def test_inventory_by_aws_accountId(self, api_v2_client, time_filter, account_id):
        """Verify if resources are returned for the specified AWS account using API v2 and confirm that all returned resources contain the correct AWS account ID.

        Given: An AWS account ID and a time filter,
        When: The inventory search API v2 is called to retrieve resources for the specified account ID,
        Then: The API should return a 200 status code, and all resources should contain the correct AWS account ID.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            account_id: The AWS account ID to retrive resources for.
        """
        filters = [
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id}

        ]
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.debug(f'payload: \n{payload}')
        api_instance = InventoryV2(api_v2_client)
        api_response = api_instance.search_inventory(json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        try:
            response_from_api = check_and_return_json_from_response(api_response)
        except ValueError:
            pytest.fail("API response is not in valid JSON format")
        try:
            response_from_api_data = response_from_api['data']
            for data in response_from_api_data:
                assert data['cloudDetails']['accountID'] == account_id, f"accoundid {account_id} is not found in {data}S"
        except KeyError as e:
            logger.info(f' response body: \n {response_from_api_data}')
            pytest.fail(f'Faild  to find key {e} in response')
