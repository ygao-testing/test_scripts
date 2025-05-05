import json
import logging
import pytest

from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response, build_dynamic_payload
from collections import defaultdict

logger = logging.getLogger(__name__)


class TestResourceInventoryEC2Instance:
    """
    Test EC2 instances in the resource inventory.

    The tests check the presence of EC2 instances in the Lacework resource inventory using different filters,
    such as resource ID, private IP, public IP, and security groups.

    A `time_filter` is used in all tests, which provides a dictionary containing:
        - `startTime`: 1 day before the current time in UTC.
        - `endTime`: The current time in UTC.
    """
    ec2_instance = defaultdict(str, {
        "InstanceId": "i-02dd5e167d6081e1a",
        "SecurityGroups": {
            "sg-04eb228e0a75128cb": {
                "GroupId": "sg-04eb228e0a75128cb",
                "GroupName": "web-server-sg"
            }
        },
        "InstanceType": "t3.micro",
        "PrivateIpAddress": "10.1.81.189",
        "Tags": {
            "Name": "mminabian_7cb194ed-web_server2",
            "Owner": "mminabian"
        }
    })
    ec2_instance_2 = defaultdict(str, {
        "InstanceId": "i-09186081f95c9e501",
        "SecurityGroups": {
            "sg-04eb228e0a75128cb": {
                "GroupId": "sg-04eb228e0a75128cb",
                "GroupName": "web-server-sg"
            },
            "sg-0deac20270702fade": {
                "GroupId": "sg-0deac20270702fade",
                "GroupName": "allow-ping-from-bastion-subnet"
            }
        },
        "InstanceType": "t2.micro",
        "PrivateIpAddress": "10.1.81.188",
        "Tags": {
            "Name": "mminabian_7cb194ed-web_server1",
            "Owner": "mminabian"
        }
    })
    ec2_instance_public = defaultdict(str, {
        "InstanceId": "i-0d0d98f4dc01e6e14",
        "SecurityGroups": {
            "sg-08b89a230016bf8ff": {
                "GroupId": "sg-08b89a230016bf8ff",
                "GroupName": "bastion-sg"
            }
        },
        "InstanceType": "t2.micro",
        "PrivateIpAddress": "10.1.61.243",
        "PublicIpAddress": "3.12.164.131",
        "Tags": {
            "Name": "mminabian_7cb194ed-bastion",
            "Owner": "mminabian"
        }
    })

    all_ec2_instances = [ec2_instance, ec2_instance_2, ec2_instance_public]
    ec2_instance_with_securit_group = {
        "sq": "sg-04eb228e0a75128cb",
        "instances": [ec2_instance, ec2_instance_2]
    }

    @pytest.mark.parametrize("ec2_instance", [ec2_instance])
    def test_inventory_search_ec2_instance_by_resourceId_v2(self, api_v2_client, time_filter, ec2_instance):
        """Verify if the EC2 instance is present in the inventory by searching with the resource ID.

        Given: An EC2 instance with a resource ID and a time filter,
        When: The inventory search API v2 is called using the EC2 instance's resource ID,
        Then: The API should return a 200 status code, and  only the EC2 instance should be present in the inventory data.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            ec2_instance: The EC2 instance to be verified.
        """
        filters = [
            {"expression": "eq", "field": "resourceId", "value": ec2_instance["InstanceId"]}
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
            for data in response_from_api['data']:
                assert data['resourceId'] == ec2_instance["InstanceId"], \
                    f"resourceId {ec2_instance['InstanceId']} is not found in {data}"
        except KeyError as e:
            logger.info(f'response body: \n{response_from_api_data}')
            pytest.fail(f'Failed to find key {e} in response')

    @pytest.mark.parametrize("ec2_instance", [ec2_instance])
    def test_inventory_search_ec2_instance_by_private_ip_address_v2(self, api_v2_client, time_filter, ec2_instance):
        """Verify if the EC2 instance is present in the inventory by searching with the private IP address.

        Given: An EC2 instance with a private IP address,
        When: The inventory search API v2 is called with resourceType as 'ec2:instance' and the EC2 instance's private IP address as filters,
        Then: The API should return a 200 status code, and the EC2 instance should be found in the inventory data with the correct private IP address.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            ec2_instance: The EC2 instance to be verified.
        """
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "eq", "field": "resourceConfig.PrivateIpAddress", "value": ec2_instance["PrivateIpAddress"]}
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
            for data in response_from_api['data']:
                assert data["resourceConfig"]["PrivateIpAddress"] == ec2_instance["PrivateIpAddress"], \
                    f'EC2 INSTANCE with privete Ip Address {data["resourceConfig"]["PrivateIpAddress"]} \
                        found in response {data} instead of {ec2_instance["PrivateIpAddress"]} '
                if data['resourceId'] == ec2_instance["InstanceId"]:
                    found = True
            assert found, f'EC2 instance {ec2_instance["InstanceId"]} with private ip address {ec2_instance["PrivateIpAddress"]} is not found in {response_from_api_data}'
        except KeyError as e:
            logger.info(f'response body: \n{response_from_api_data}')
            pytest.fail(f'Failed to find key {e} in response')

    @pytest.mark.parametrize("ec2_instance", [ec2_instance_public])
    def test_inventory_search_ec2_instance_by_public_ip_address_v2(self, api_v2_client, time_filter, ec2_instance):
        """Verify if the EC2 instance is present in the inventory by searching with the public IP address.

        Given: An EC2 instance with a public IP address,
        When: The inventory search API v2 is called with resourceType as 'ec2:instance' and the EC2 instance's public IP address as filters,
        Then: The API should return a 200 status code, and the EC2 instance should be found in the inventory data with the correct public IP address.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            ec2_instance: The EC2 instance to be verified.
        """
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "eq", "field": "resourceConfig.PublicIpAddress", "value": ec2_instance["PublicIpAddress"]}
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
            for data in response_from_api['data']:
                assert data["resourceConfig"]["PublicIpAddress"] == ec2_instance["PublicIpAddress"], \
                    f'EC2 INSTANCE with public Ip Address {data["resourceConfig"]["PublicIpAddress"]} ' \
                    f'found in response {data} instead of {ec2_instance["PublicIpAddress"]}'
                assert data['resourceId'] == ec2_instance["InstanceId"], \
                    f'Expected EC2 instance {ec2_instance["InstanceId"]} with public ip address {ec2_instance["PublicIpAddress"]}' \
                    f'but EC2 insatce {data["resourceId"]} with public ip address {ec2_instance["PublicIpAddress"]} is found '\
                    f'in response: \n {data}'
        except KeyError as e:
            logger.info(f'response body: \n{response_from_api_data}')
            pytest.fail(f'Failed to find key {e} in response')

    @pytest.mark.parametrize("all_ec2_instances", [all_ec2_instances])
    def test_inventory_find_all_ec2_instance_v2(self, api_v2_client, time_filter, all_ec2_instances):
        """Verify if all expected EC2 instances are returned in the inventory by searching with the account ID.

        Given: A list of EC2 instances and an account ID,
        When: The inventory search API v2 is called with resourceType as 'ec2:instance' and the account ID as filters,
        Then: The API should return a 200 status code, and all expected EC2 instances should be present in the inventory, without any missing or unexpected instances.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            all_ec2_instances: List of expected EC2 instances.
        """
        expected_instance_ids = {instance["InstanceId"] for instance in all_ec2_instances}
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            # The below line should be removed after implementation of getting list of ec2 from aws
            {"expression": "eq", "field": "cloudDetails.accountID", "value": "886436945382"}
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
            response_instance_ids = {data["resourceId"] for data in response_from_api_data}
            missing_instance = expected_instance_ids - response_instance_ids
            assert not missing_instance, f"Missing EC2 instances: {missing_instance} " \
                f" from expected instances: {expected_instance_ids}"
            # extra_instances = response_instance_ids - expected_instance_ids
            # assert not extra_instances, f"In addition to expected instances, Unexpected EC2 instances found in inventory: {extra_instances} "
        except KeyError as e:
            logger.info(f'response body: \n{response_from_api_data}')
            pytest.fail(f'Failed to find key {e} in response')

    @pytest.mark.parametrize("ec2_instance_with_securit_group", [ec2_instance_with_securit_group])
    def test_inventory_search_ec2_by_security_groups_v2(self, api_v2_client, time_filter, ec2_instance_with_securit_group):
        """Verify if EC2 instances associated with a specific security group are present in the inventory.

        Given: A security group and a list of EC2 instances associated with it,
        When: The inventory search API v2 is called with resourceType as 'ec2:instance' and the security group as filters,
        Then: The API should return a 200 status code, and all EC2 instances associated with the security group should be present in the inventory data.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            ec2_instance_with_securit_group: Dictionary containing the security group and associated EC2 instances.
        """
        expected_instance_ids = {instance["InstanceId"] for instance in ec2_instance_with_securit_group["instances"]}
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "rlike", "field": "resourceConfig.SecurityGroups", "value": f'.*{ec2_instance_with_securit_group["sq"]}.*'}
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
            response_instance_ids = {data["resourceId"] for data in response_from_api_data}
            missing_instances = expected_instance_ids - response_instance_ids
            assert not missing_instances, f"Missing EC2 instances: {missing_instances} " \
                f" from expected instances: {expected_instance_ids}"
            extra_instances = response_instance_ids - expected_instance_ids
            assert not extra_instances, f"In addition to expected instances, Unexpected EC2 instances found in inventory: {extra_instances} "
        except KeyError as e:
            logger.info(f'response body: \n{response_from_api_data}')
            pytest.fail(f'Failed to find key {e} in response')

    @pytest.mark.parametrize("all_ec2_instances", [all_ec2_instances])
    def test_inventory_search_ec2_by_nosecurity_groups(self, api_v2_client, time_filter, all_ec2_instances):
        """Verify that EC2 instances without a specific security group are correctly retrieved from the inventory.

        Given: A list of EC2 instances with associated security groups,
        When: The test finds the first security group from an instance in the list of EC2 instances and makes an API call to retrieve all EC2 instances that do not have this security group,
        Then: If no EC2 instance in the API response contains the specific security group, the test passes.

        Args:
            api_v2_client: API client for interacting with the Lacework inventory API v2.
            time_filter: Time filter for querying the inventory.
            all_ec2_instances: List of EC2 instances.
        """
        not_expected_sq = None
        for instance in all_ec2_instances:
            if "SecurityGroups" in instance and instance["SecurityGroups"]:  # Check if SecurityGroups exist and is not empty
                not_expected_sq = next(iter(instance["SecurityGroups"]))  # Get the first key in SecurityGroups
                break
        # Skip the test if no security group was found
        if not_expected_sq is None:
            pytest.skip("No EC2 instance found with a security group")
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "not_rlike", "field": "resourceConfig.SecurityGroups", "value": f".*{not_expected_sq}.*"}
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
            for data in response_from_api_data:
                if "resourceConfig" in data and "SecurityGroups" in data["resourceConfig"]:
                    security_groups = data["resourceConfig"]["SecurityGroups"]
            # Ensure the security group key is not in this instance's security groups
                for sg in security_groups:
                    if not_expected_sq[1] == sg["GroupId"]:  # Compare the security group key with GroupId in the list
                        pytest.fail(f"EC2 instance {data['resourceId']} has {not_expected_sq} security group")
            # If no EC2 instance with the security group is found, the test passes
            logger.info(f"All EC2 instances in the inventory API response do not have the security group {not_expected_sq}")
        except KeyError as e:
            logger.info(f'response body: \n{response_from_api_data}')
            pytest.fail(f'Failed to find key {e} in response')
