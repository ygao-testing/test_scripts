import pytest
import logging
import os
import json
import time

from datetime import datetime
from fortiqa.libs.lw.apiv1.api_client.deployments.deployments import Deployments
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations
from fortiqa.tests.e2e.cloud_logs.conftest import apply_tf_modules, destroy_tf_modules
from fortiqa.tests.e2e.integrations.cloud_accounts.utils import get_service_account_token
from fortiqa.libs.lw.apiv1.helpers.cloud_logs.gcp_auditlog_helper import AuditLogHelper
from fortiqa.libs.gcp.gcp_publisher_helper import PubliserHelper
from fortiqa.libs.gcp.gcp_compute_helper import ComputeHelper
from dataclasses import dataclass
from typing import Optional, List, Dict


logger = logging.getLogger(__name__)

gcp_deploy_payload_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/gcp_deploy_payload.json'))
gcp_delete_deployment_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/gcp_delete_deployment.json'))
gcp_credential_json_file = os.path.abspath(
    os.path.expanduser('./e2e/cloud_logs/gcp_auditlog/credentials.json'))


@pytest.fixture(scope='package')
def gcp_env_variables(gcp_creds) -> None:
    """Fixture sets and deletes GCP credentials as env variables."""
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = gcp_credential_json_file
    os.environ['TF_VAR_GCP_PROJECT_ID'] = gcp_creds['project_id']
    yield
    del os.environ['GOOGLE_APPLICATION_CREDENTIALS']
    del os.environ['TF_VAR_GCP_PROJECT_ID']


@dataclass
class GCPIntegrationContext:
    """Data class to store GCP integration context information.

    Attributes:
        deployment_client: Deployments client instance
        deployment_payload: GCP credentials dictionary
        deployment_id: Optional string containing deployment ID
        workspace_ids: Optional list of workspace IDs
    """
    deployment_client: Deployments
    deployment_payload: Dict
    deployment_id: Optional[str] = None
    workspace_ids: Optional[List[str]] = None
    xfail: Optional[bool] = False


@pytest.fixture(scope="package")
def gcp_creds():
    """Fixture to provide GCP credentials for integration testing.

    This fixture load service account credentials from saved json file,
    generates an access token, and returns a dictionary containing the necessary
    GCP credentials for deployment.


    Returns:
        dict: Dictionary containing GCP credentials with the following keys:
            - access_token (str): GCP access token for authentication
            - project_id (str): GCP project ID
            - org_id (str): GCP organization ID
    """
    path = gcp_credential_json_file
    access_token = get_service_account_token(path)
    with open(gcp_credential_json_file, "r") as file:
        data = json.load(file)
        logger.info(data)
        return {
            'access_token': access_token,
            'project_id': data['project_id'],
            'org_id': data['org_id'],
        }


@pytest.fixture(scope="package")
def gcp_integration_context(api_v1_client, gcp_creds):
    """
    Fixture that provides a GCP integration context and handles cleanup.

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        gcp_creds: GCP credentials for the service account
    Yields:
        GCPIntegrationContext: Context object containing the deployment client and deployment information

    Cleanup:
        Deletes the deployment after the test
    """
    # Create deployment client
    deployment_client = Deployments(api_v1_client)

    gcp_deploy_payload = json.load(open(gcp_deploy_payload_json_file, 'r'))
    gcp_integration_type = ["gcp_audit_log"]
    gcp_deploy_payload['integrations'] = gcp_integration_type
    gcp_deploy_payload['data'].update({
        'access_token': gcp_creds['access_token'],
        'project_id': gcp_creds['project_id'],
        'org_id': gcp_creds['org_id'],
    })
    logger.info({'gcp_deploy_payload': gcp_deploy_payload})
    try:
        context = GCPIntegrationContext(
            deployment_client=deployment_client,
            deployment_payload=gcp_deploy_payload,
        )

        yield context
    finally:
        # Cleanup after test
        if context.deployment_id and context.workspace_ids:
            try:
                delete_payload = json.load(open(gcp_delete_deployment_json_file, 'r'))
                delete_payload['data'].update({
                    'access_token': get_service_account_token(gcp_credential_json_file),  # Tests take too long, and access_token generated before expired
                    'project_id': gcp_creds['project_id'],
                    'org_id': gcp_creds['org_id'],
                })
                delete_payload['integrations'] = gcp_integration_type
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
def on_board_gcp_auditlog_integration(api_v1_client, gcp_integration_context, gcp_creds):
    """Fixture to onboard GCP AuditLog integration"""
    time_stamp_before_integration = int(datetime.now().timestamp() * 1000.0)
    integration_payload = json.loads(json.dumps(gcp_integration_context.deployment_payload))
    deployment_client = gcp_integration_context.deployment_client
    resp = deployment_client.run_integration(
        payload=integration_payload
    )
    logger.info(f"Integration request status: {resp.status_code}")
    logger.debug(f"Integration response:\n{resp.text}")
    assert resp.status_code == 201, (
                f"Integration request failed with status {resp.status_code}:\n"
                f"Response: {resp.text}\n"
                f"Request payload: {json.dumps(integration_payload, indent=4)}"
            )

    # Store deployment information for cleanup
    deployment_data = resp.json().get('data', {})
    gcp_integration_context.deployment_id = deployment_data.get('deployment_id')
    logger.info(f"Deployment ID: {gcp_integration_context.deployment_id}")

    integration_data = deployment_client.get_sse(channel=gcp_integration_context.deployment_id)

    # Verify integration status
    resp = deployment_client.pull_integration(
        deployment_id=gcp_integration_context.deployment_id
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
    gcp_integration_context.workspace_ids = workspace_ids

    # wait for tf files to be generated
    time.sleep(3)
    for workspace_id in workspace_ids:
        file_path = gcp_integration_context.deployment_client.download_integration_tf_files(
            deployment_id=gcp_integration_context.deployment_id,
            workspace_id=workspace_id
        )
        # Check if the tf file is not empty
        assert os.path.getsize(file_path) != 0, f"Downloaded tf file is empty: {file_path}"
        os.remove(file_path)

    # Wait for a new Integration appear after run_integration
    account_found = AuditLogHelper(user_api=api_v1_client).wait_until_gcp_audit_log_account_added_after_timestamp_with_project_id(timestamp=time_stamp_before_integration,
                                                                                                                                  gcp_project_id=gcp_creds['project_id'],)
    Integrations(api_v1_client).wait_until_status_success(intg_guid=account_found['INTG_GUID'])
    integration_topic_id = account_found['DATA']['TOPIC_ID']
    gcp_pub_helper = PubliserHelper(project_id=gcp_creds['project_id'], credentials_path=gcp_credential_json_file)
    gcp_pub_helper.wait_until_pub_appear(topic_id=integration_topic_id)
    return integration_topic_id


@pytest.fixture(scope="package")
def wait_for_auditlog_log(api_v1_client, on_board_gcp_auditlog_integration, create_gcp_audit_log_events, gcp_creds):
    """Fixture to wait until CloudLog logs appear inside Lacework"""
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    auditlog_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    auditlog_helper.wait_until_specific_event_resource_appear(gcp_project_id=gcp_creds['project_id'],
                                                              resource_name=create_gcp_audit_log_events['gcp_instance_name'],
                                                              method_name="v1.compute.instances.delete",
                                                              timeout=6000)


@pytest.fixture(scope="package")
def create_gcp_audit_log_events(cloudlog_tf_root, gcp_env_variables, on_board_gcp_auditlog_integration, gcp_creds):
    """
    Fixture to:
    1. Deploy GCP resources (Compute VM, Firewall)
    2. Use GCP API to do operations on deployed resources
    3. Destroy resources before onboarding GCP AuditLog Integration
    """
    resources = {}
    tf_module = ["gcp_vm"]
    resources = apply_tf_modules(tf_module, cloudlog_tf_root)
    tf_output = resources['gcp_vm'].get('tf').output()
    gcp_instance_name = tf_output['agent_host_name']
    gcp_instance_zone = tf_output['zone']
    compute_helper = ComputeHelper(project_id=gcp_creds['project_id'],
                                   zone=gcp_instance_zone,
                                   credentials_path=gcp_credential_json_file)
    compute_helper.stop_instance(instance_name=gcp_instance_name)
    saved_resources = dict(
        deployment_timestamp=resources['gcp_vm']['deployment_timestamp'],
        deployment_time=resources['gcp_vm']['deployment_time'],
        gcp_instance_name=gcp_instance_name,
        gcp_instance_zone=gcp_instance_zone,
        gcp_instance_id=tf_output['agent_host_instance_id'],
        gcp_firewall_name=tf_output['firewall_name']
    )
    destroy_tf_modules(resources)
    return saved_resources
