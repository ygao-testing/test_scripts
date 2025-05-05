import logging
import pytest

from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL
from fortiqa.libs.aws.iam import IAMHelper
from fortiqa.libs.aws.s3 import S3Helper
from fortiqa.libs.aws.ec2 import EC2Helper

logger = logging.getLogger(__name__)


def test_show_all_storage_assets_of_type_aws_accessible_via_identity(api_v1_client):
    """
    Verify that stored query Show all storage assets of type AWS accessible via identity works as expected

    Given: API V1 Client
    When: Call GraphQL API to simulate the stored query
    Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='DATA')
    query.add_filter(key="cloudServiceProvider",
                     operator=ComparisonOperator.IS_IN,
                     value=["AWS"])
    query.add_connector(type="IDENTITY")
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    error_messages = ""
    if response.status_code != 200:
        error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {response.text}"
    if "errors" in response.json():
        error_messages += f"\nExpect no error returned, but got {response.json()['errors'][0]['message']}"
    if response.elapsed.total_seconds() > 7:
        error_messages += f"\nResponse time: {
            response.elapsed.total_seconds()} is greater than 7 seconds"
    s3_buckets_that_can_be_accessed = S3Helper().list_all_s3_buckets_that_is_accessible()
    for s3_bucket in s3_buckets_that_can_be_accessed:
        found = False
        for resource in response.json()['data']['resources']['edges']:
            if s3_bucket in resource['node']['resourceId']:
                found = True
                break
        if not found:
            error_messages += f"\nExpected to find {s3_bucket} in Lacework, but found None"
        assert error_messages, error_messages


def test_show_all_aws_identities_that_can_access_storage_assets(api_v1_client):
    """
    Verify that stored query Show all AWS identities that can access storage assets works as expected

    Given: API V1 Client
    When: Call GraphQL API to simulate the stored query
    Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="cloudServiceProvider",
                     operator=ComparisonOperator.IS_IN,
                     value=["AWS"])
    query.add_connector(type="DATA")
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    error_messages = ""
    if response.status_code != 200:
        error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {response.text}"
    if "errors" in response.json():
        error_messages += f"\nExpect no error returned, but got {response.json()['errors'][0]['message']}"
    if response.elapsed.total_seconds() > 7:
        error_messages += f"\nResponse time: {
            response.elapsed.total_seconds()} is greater than 7 seconds"
    iam_users_that_can_access_s3 = IAMHelper().list_iam_users_have_access_to_specic_s3_bucket()
    for iam_user_arn in iam_users_that_can_access_s3:
        found = False
        for resource in response.json()['data']['resources']['edges']:
            if iam_user_arn == resource['node']['urn']:
                found = True
                break
        if not found:
            error_messages += f"\nExpected to find {iam_user_arn} in Lacework, but found None"
        assert error_messages, error_messages


def test_show_all_hosts_that_are_internet_exposed_to_a_specific_cidr_range_behind_a_vpn_or_other_gateways(api_v1_client):
    """
    Verify that stored query Show all hosts that are internet exposed to a specific CIDR range behind a VPN or other gateways

    Given: API V1 Client
    When: Call GraphQL API to simulate the stored query
    Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="accessibleFromNetworkRangeV2",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=["0.0.0.0/0"])
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    error_messages = ""
    if response.status_code != 200:
        error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {response.text}"
    if "errors" in response.json():
        error_messages += f"\nExpect no error returned, but got {response.json()['errors'][0]['message']}"
    if response.elapsed.total_seconds() > 7:
        error_messages += f"\nResponse time: {
            response.elapsed.total_seconds()} is greater than 7 seconds"
    vulnerable_ec2_instances = EC2Helper(region="us-west-1").list_ec2_instances_exposed_to_public()
    for ec2_instance in vulnerable_ec2_instances:
        found = False
        for resource in response.json()['data']['resources']['edges']:
            if ec2_instance['InstanceId'] == resource['node']['resourceId']:
                found = True
                break
        if not found:
            error_messages += f"\nExpected to find {ec2_instance} in Lacework, but found None"
        assert error_messages, error_messages


@pytest.mark.parametrize("risk_score", [0])
def test_show_high_risk_hosts_with_ssh_port_open_and_exposed_to_the_public_internet_due_to_inbound_access(api_v1_client, risk_score):
    """
    Verify that stored query Show all high risk hosts with ssh port open and exposed to the public internet due to inbound access

    Given: API V1 Client
    When: Call GraphQL API to simulate the stored query
    Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="accessibleFromNetworkRangeV2",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=["0.0.0.0/0"])
    query.add_filter(key="openPortsV2",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=["22"])
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="score",
                                           operator=ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
                                           value=risk_score)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    error_messages = ""
    if response.status_code != 200:
        error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {response.text}"
    if "errors" in response.json():
        error_messages += f"\nExpect no error returned, but got {response.json()['errors'][0]['message']}"
    if response.elapsed.total_seconds() > 7:
        error_messages += f"\nResponse time: {
            response.elapsed.total_seconds()} is greater than 7 seconds"
    vulnerable_ec2_instances = EC2Helper(region="us-west-1").list_ec2_instances_exposed_to_public_with_ssh_port_open()
    for ec2_instance in vulnerable_ec2_instances:
        found = False
        for resource in response.json()['data']['resources']['edges']:
            if ec2_instance['InstanceId'] == resource['node']['resourceId']:
                found = True
                break
        if not found:
            error_messages += f"\nExpected to find {ec2_instance} in Lacework, but found None"
        assert error_messages, error_messages
