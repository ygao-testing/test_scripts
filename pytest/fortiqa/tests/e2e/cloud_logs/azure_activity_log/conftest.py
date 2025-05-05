import pytest
import logging
import os
import json
import re

from datetime import datetime
from fortiqa.libs.lw.apiv1.api_client.deployments.deployments import Deployments
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations
from fortiqa.tests.e2e.cloud_logs.conftest import apply_tf_modules, destroy_tf_modules
from fortiqa.libs.lw.apiv1.helpers.cloud_logs.azure_activity_log_helper import ActivityLogHelper
from fortiqa.libs.azure.storage_management import StorageManagementHelper
from fortiqa.libs.azure.subscription_helper import SubscriptionHelper
from dataclasses import dataclass
from typing import Optional, List, Dict


logger = logging.getLogger(__name__)

azure_deploy_payload_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/azure_deploy_payload.json'))
azure_delete_deployment_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/azure_delete_deployment.json'))


@pytest.fixture(scope='package')
def azure_env_variables(azure_creds) -> None:
    """Fixture sets and deletes Azure credentials as env variables."""
    os.environ["ARM_CLIENT_ID"] = azure_creds.client_id
    os.environ["ARM_CLIENT_SECRET"] = azure_creds.client_secret
    os.environ["ARM_TENANT_ID"] = azure_creds.tenant_id
    os.environ["ARM_SUBSCRIPTION_ID"] = azure_creds.subscription_id
    yield
    del os.environ["ARM_CLIENT_ID"]
    del os.environ["ARM_CLIENT_SECRET"]
    del os.environ["ARM_TENANT_ID"]
    del os.environ["ARM_SUBSCRIPTION_ID"]


@dataclass
class AzureIntegrationContext:
    """Data class to store Azure integration context information.

    Attributes:
        deployment_client: Deployments client instance
        deployment_payload: Azure credentials dictionary
        deployment_id: Optional string containing deployment ID
        workspace_ids: Optional list of workspace IDs
    """
    deployment_client: Deployments
    deployment_payload: Dict
    deployment_id: Optional[str] = None
    workspace_ids: Optional[List[str]] = None
    xfail: Optional[bool] = False

    def __post_init__(self):
        if self.workspace_ids is None:
            self.workspace_ids = []


@pytest.fixture(scope="package")
def azure_creds(azure_account):
    """Fixture to provide Azure credentials for integration testing.

    Returns:
        AzureAccountSettings: Azure credentials with specified privilege level
    """
    return azure_account


@pytest.fixture(scope="package")
def azure_subscription_name(azure_creds):
    """Fixture to return Azure subscription Name"""
    return SubscriptionHelper(azure_creds.subscription_id, azure_creds.credentials).fetch_current_subscription_name()


@pytest.fixture(scope="package")
def azure_integration_context(api_v1_client, azure_creds):
    """Fixture that provides an Azure integration context and handles cleanup.

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        azure_creds: Azure credentials fixture
    Yield:
        AzureIntegrationContext: Context object containing the deployment client and deployment information
    Cleanup:
        Deletes the deployment after the test
    """
    azure_deployment_payload = json.load(open(azure_deploy_payload_json_file, 'r'))
    azure_deployment_payload['data'].update({
        'client_id': azure_creds.client_id,
        'client_secret': azure_creds.client_secret,
        'tenant_id': azure_creds.tenant_id,
        'subscription_id': azure_creds.subscription_id,
    })
    azure_integration_type = ["azure_activity_log"]
    azure_deployment_payload['integrations'] = azure_integration_type
    try:
        # Create the context with the deployment client
        context = AzureIntegrationContext(
            deployment_client=Deployments(api_v1_client),
            deployment_payload=azure_deployment_payload
        )

        yield context
    finally:
        # Cleanup after test
        if context.deployment_id and context.workspace_ids:
            try:
                delete_payload = json.load(open(azure_delete_deployment_json_file, 'r'))
                delete_payload['data'].update({
                    'client_id': azure_creds.client_id,
                    'client_secret': azure_creds.client_secret,
                    'tenant_id': azure_creds.tenant_id,
                    'subscription_id': azure_creds.subscription_id,
                })
                delete_payload['integrations'] = azure_integration_type
                delete_payload['workspace_ids'] = context.workspace_ids

                logger.info(f"Cleaning up deployment {context.deployment_id}")
                resp = context.deployment_client.delete_integration(
                    deployment_id=context.deployment_id,
                    payload=delete_payload
                )
                assert resp.status_code == 200, f'Failed to delete integration {context.deployment_id} resp: {resp.text}'

                # Get delete status
                try:
                    delete_data = context.deployment_client.get_sse(channel=context.deployment_id, timeout=600)
                except Exception as e:
                    logger.error(f"Failed to get SSE data for deployment {context.deployment_id}: {e}")
                    delete_data = {}
                resp = context.deployment_client.pull_integration(deployment_id=context.deployment_id)

                integration_logs = "\n".join(
                    f"Name: {integration.get('name', 'N/A')}, "
                    f"Status: {integration.get('status', 'N/A')}, "
                    f"Error: {integration.get('error', 'N/A')}"
                    for integration in resp['integrations']
                )
                logger.debug(f'After delete integrations: {integration_logs=}')

                assert (
                        resp['status'] == 'rolled-back' and
                        all(integration['status'] == 'rolled-back' for integration in resp['integrations'])
                ), (
                    'Not all delete integrations were successful\n'
                    f"{resp['status']=}\n"
                    f"{integration_logs=}\n"
                    f"SSE response data:\n{json.dumps(delete_data, indent=4)}"
                )
            except Exception as e:
                logger.error(f"Failed to cleanup deployment {context.deployment_id}: {e}")
                raise
        elif not context.xfail:
            if not context.deployment_id:
                logger.error("No deployment ID found in context")
            if not context.workspace_ids:
                logger.error("No workspace IDs found in context")


@pytest.fixture(scope="package")
def on_board_azure_activitylog_integration(api_v1_client, azure_integration_context, azure_creds):
    """Fixture to onboard Azure ActivityLog integration"""
    time_stamp_before_integration = int(datetime.now().timestamp() * 1000.0)
    # Prepare integration payload
    integration_payload = json.loads(json.dumps(azure_integration_context.deployment_payload))
    logger.info(f"{integration_payload=}")
    # Run integration
    deployment_client = azure_integration_context.deployment_client
    resp = deployment_client.run_integration(
        payload=integration_payload
    )
    logger.info(f"Integration request status: {resp.status_code}")
    logger.debug(f"Integration response:\n{resp.text}")

    # Verify integration response
    assert resp.status_code == 201, (
        f"Integration request failed with status {resp.status_code}:\n"
        f"Response: {resp.text}\n"
        f"Request payload: {json.dumps(integration_payload, indent=4)}"
    )

    # Store deployment information for cleanup
    deployment_data = resp.json().get('data', {})
    azure_integration_context.deployment_id = deployment_data.get('deployment_id')
    logger.info(f"Deployment ID: {azure_integration_context.deployment_id}")

    integration_data = deployment_client.get_sse(channel=azure_integration_context.deployment_id)

    # Verify integration status
    resp = deployment_client.pull_integration(
        deployment_id=azure_integration_context.deployment_id
    )

    integration_logs = "\n".join(
        f"Name: {integration.get('name', 'N/A')}, "
        f"Status: {integration.get('status', 'N/A')}, "
        f"Error: {integration.get('error', 'N/A')}"
        for integration in resp['integrations']
    )
    logger.debug(f'Integration status: {integration_logs=}')

    assert (
        resp['status'] == 'succeeded' and
        all(integration['status'] == 'succeeded' for integration in resp['integrations'])
    ), (
        'Integration failed:'
        f"{resp['status']=} "
        f"{integration_logs=} "
        f"SSE message: {integration_data['messages']}"
    )
    workspace_ids = [integration['workspace_id'] for integration in resp['integrations']]
    azure_integration_context.workspace_ids = workspace_ids

    for workspace_id in workspace_ids:
        file_path = azure_integration_context.deployment_client.download_integration_tf_files(
            deployment_id=azure_integration_context.deployment_id,
            workspace_id=workspace_id
        )
        # Check if the tf file is not empty
        assert os.path.getsize(file_path) != 0, f"Downloaded tf file is empty: {file_path}"
        os.remove(file_path)

    # Wait for a new Integration appear after run_integration
    account_found = ActivityLogHelper(user_api=api_v1_client).wait_until_azure_activity_log_account_added_after_timestamp_with_tenant_id(timestamp=time_stamp_before_integration,
                                                                                                                                         tenant_id=azure_creds.tenant_id,)
    Integrations(api_v1_client).wait_until_status_success(intg_guid=account_found['INTG_GUID'])
    # Check if resources created by integration appear inside Azure Portal
    integration_queue_url = account_found['DATA']['QUEUE_URL']
    logger.info(f"Integration Queue URL found for integration: {integration_queue_url}")
    match = re.search(r"https://([a-z0-9]+)\.queue\.core\.windows\.net", integration_queue_url)
    storage_account_name = None
    if match:
        storage_account_name = match.group(1)
    else:
        raise Exception("Not finding storage account info from Azure Integration")

    storage_account_helper = StorageManagementHelper(subscription_id=azure_creds.subscription_id,
                                                     azure_credentials=azure_creds.credentials
                                                     )
    storage_account_helper.wait_until_storage_account_created(storage_account_name=storage_account_name)
    return storage_account_name


@pytest.fixture(scope="package")
def wait_for_activit_log(api_v1_client, on_board_azure_activitylog_integration, create_azure_activity_log_events, azure_creds, azure_subscription_name):
    """Fixture to wait until ActivityLog logs appear inside Lacework"""
    resource_deploy_timestamp = create_azure_activity_log_events['deployment_timestamp']
    activity_log_helper = ActivityLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    activity_log_helper.wait_until_specific_event_resource_appear(azure_subscription_name=azure_subscription_name,
                                                                  resource_name=create_azure_activity_log_events['azure_resource_group_name'],
                                                                  operation_name="MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE",
                                                                  timeout=6000)


@pytest.fixture(scope="package")
def create_azure_activity_log_events(cloudlog_tf_root, azure_env_variables, on_board_azure_activitylog_integration, azure_creds):
    """
    Fixture to:
    1. Deploy Azure resources (Resource Group, Virtual Machine, Virtual Network, Subnet, Security Group)
    2. Use Boto3 to do operations on deployed resources
    3. Destroy resources before onboarding AWS account
    """
    resources = {}
    tf_module = ["azure_vm"]
    resources = apply_tf_modules(tf_module, cloudlog_tf_root)
    tf_output = resources['azure_vm'].get('tf').output()
    saved_resources = dict(
        deployment_timestamp=resources['azure_vm']['deployment_timestamp'],
        deployment_time=resources['azure_vm']['deployment_time'],
        azure_instance_name=tf_output['agent_host_name'],
        azure_virtual_network_name=tf_output['agent_virtual_network_name'],
        azure_subnet_name=tf_output['agent_subnet_name'],
        azure_resource_group_name=tf_output['agent_resource_group_name'],
        azure_network_interface_name=tf_output['agent_network_interface_name']
    )
    destroy_tf_modules(resources)
    return saved_resources
