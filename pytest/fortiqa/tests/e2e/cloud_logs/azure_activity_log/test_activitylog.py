import logging
import pytest

from fortiqa.libs.lw.apiv1.helpers.cloud_logs.azure_activity_log_helper import ActivityLogHelper

logger = logging.getLogger(__name__)


def test_activity_log_events(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> Events graph

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->Events graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog Event graph")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_event_data_by_azure_subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside Event graph, but found None"


def test_activity_log_unique_users(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> Usernames graph

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->Unique user graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog Unique Usernames graph")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_unique_user_by_azure_subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside Unique Usernames graph, but found None"


def test_activity_log_unique_operations(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> Unique operations graph

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->Unique operations graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog Unique operations graph")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_unique_operations_by_azure_subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside Unique operations graph, but found None"


def test_activity_log_unique_subscriptions(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> Unique subscriptions graph

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->Unique subscriptions graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog Unique subscriptions graph")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_unique_subscriptions_by_azure_subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside Unique subscriptions graph, but found None"


def test_activity_log_unique_regions(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> Unique Regions graph

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->Unique Regions graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog Unique Regions graph")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_unique_regions_by_azure_subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside Unique Regions graph, but found None"


def test_activity_log_unique_resource_types(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> Unique Resource Types graph

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->Unique Resource Types graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog Unique Resource Types graph")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_unique_resource_types_by_azure_subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside Unique Resource Types graph, but found None"


def test_activity_log_user_details(api_v1_client, create_azure_activity_log_events, azure_creds, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog Page -> User details dashboard

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog->User details graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
    """
    logger.info("Testing ActivityLog User details dashboard")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = activity_log_helper.get_activity_log_user_details_by_Subscription_name(azure_subscription_name)
    assert data, "Expected to find data inside User details dashboard, but found None"


@pytest.mark.parametrize("expected_event", [
    "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
    "MICROSOFT.NETWORK/VIRTUALNETWORKS/SUBNETS/WRITE",
    "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE",
    "MICROSOFT.NETWORK/VIRTUALNETWORKS/WRITE",
    "MICROSOFT.NETWORK/VIRTUALNETWORKS/SUBNETS/DELETE",
    "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE",
    "MICROSOFT.NETWORK/VIRTUALNETWORKS/DELETE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE",
    "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"
])
def test_activity_log_logs(api_v1_client, create_azure_activity_log_events, azure_creds, expected_event, wait_for_activit_log, azure_subscription_name):
    """Test case for Azure ActivityLog logs to check operation name and resource name

    Given: Azure ActivityLog integration finished, Azure resources deployed and operated
    When: Check Cloud Logs->ActivityLog
    Then: Expected Event Name should appear

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_azure_activity_log_events: Deployed Azure resources
        azure_creds: Azure account is being used
        expected_event: Expected Event_Name
    """
    logger.info(f"Testing {expected_event}...")
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    resource_deploy_time = create_azure_activity_log_events['deployment_time']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    timeout = 7200
    resource_to_check = None
    if "VIRTUALMACHINES" in expected_event:
        resource_to_check = create_azure_activity_log_events['azure_instance_name']
    elif "NETWORKINTERFACES" in expected_event:
        resource_to_check = create_azure_activity_log_events['azure_network_interface_name']
    elif "SUBNETS" in expected_event:
        resource_to_check = create_azure_activity_log_events['azure_subnet_name']
    elif "VIRTUALNETWORKS" in expected_event:
        resource_to_check = create_azure_activity_log_events['azure_virtual_network_name']
    elif "RESOURCEGROUPS" in expected_event:
        resource_to_check = create_azure_activity_log_events['azure_resource_group_name']
    activity_log_helper.wait_until_specific_event_resource_appear_before_timestamp(azure_subscription_name=azure_subscription_name,
                                                                                   resource_name=resource_to_check,
                                                                                   operation_name=expected_event,
                                                                                   wait_until=timeout+resource_deploy_time)
