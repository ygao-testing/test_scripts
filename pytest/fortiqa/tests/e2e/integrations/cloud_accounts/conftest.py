import os
import json
import pytest
import logging
import time
import random
import string
import yaml
import tempfile
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict
from fortiqa.libs.lw.apiv1.api_client.deployments.deployments import Deployments
from fortiqa.libs.aws.iam import IAMHelper
from fortiqa.libs.aws.sts import STSHelper
from fortiqa.libs.config import AzureAccountSettings
from .utils import get_service_account_token

logger = logging.getLogger(__name__)

gcp_deploy_payload_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/gcp_deploy_payload.json'))
gcp_delete_deployment_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/gcp_delete_deployment.json'))

# Constants
random_id = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
aws_deployment_payload_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/payload_template.json'))
aws_delete_deployment_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/delete_deployment.json'))
azure_deploy_payload_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/azure_deploy_payload.json'))
azure_delete_deployment_json_file = os.path.abspath(
    os.path.expanduser('./e2e/integrations/cloud_accounts/data/azure_delete_deployment.json'))


@dataclass
class AWSIntegrationContext:
    """Data class to store AWS integration context information.

    Attributes:
        deployment_client: Deployments client instance
        active_session: Optional dictionary containing active session information
        deployment_id: Optional string containing deployment ID
        workspace_ids: Optional list of workspace IDs
    """
    deployment_client: Deployments
    active_session: Optional[Dict] = None
    deployment_id: Optional[str] = None
    workspace_ids: Optional[List[str]] = None

    def __post_init__(self):
        if self.workspace_ids is None:
            self.workspace_ids = []


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


@pytest.fixture(scope="function", params=[None], ids=lambda x: f"missing_permission={x}" if x else '')
def missing_permission(request):
    """Fixture to test scenarios with missing permissions.

    Args:
        request: pytest request object

    Returns:
        Optional[str]: The permission to be removed from the policy, None by default
    """
    return request.param


@pytest.fixture(scope="function")
def ecr_onboardingauth_type(request):
    """Fixture to test scenarios with different authentication types for ECR onboarding.

    Args:
        request: pytest request object

    Returns:
        str: The authentication type to be used for the test
    """
    return request.param


@pytest.fixture(scope="function")
def iam_policies(aws_account, missing_permission, integration_type):
    """Fixture to create IAM policies for testing.

    This fixture creates IAM policies based on JSON templates and optionally removes
    specified permissions for testing missing permission scenarios.

    Args:
        aws_account: AWS account fixture
        missing_permission: Permission to be removed from the policy
        integration_type: Str of integration types to create policies for

    Yields:
        list: List of created IAM policies

    Cleanup:
        Deletes the created IAM policies after the test
    """
    policy_mapping = {
        'aws_cloudtrail': './e2e/integrations/cloud_accounts/data/policies/cloudtrail.json',
        'aws_config': './e2e/integrations/cloud_accounts/data/policies/configuration.json',
        'aws_agentless': './e2e/integrations/cloud_accounts/data/policies/agentless.json',
    }
    integration_type = integration_type.split(',')

    policy_json_files = []
    for integration in integration_type:
        if integration in policy_mapping:
            policy_json_files.append(os.path.abspath(os.path.expanduser(policy_mapping[integration])))

    iam_helper = IAMHelper(aws_credentials=aws_account.credentials)
    iam_policies = []
    random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    for json_file_path in policy_json_files:
        with open(json_file_path, 'r') as policy_file:
            policy = json.load(policy_file)
            policy_name = f'fortiqa_{random_id}_{policy["Statement"][0]["Sid"]}'
            if missing_permission and missing_permission in policy['Statement'][0]['Action']:
                policy['Statement'][0]['Action'].remove(missing_permission)
                policy_name = f'fortiqa_{random_id}_{policy["Statement"][0]["Sid"]}_missing_{missing_permission}'.replace(
                    ':', '_')
            logger.debug(f'Creating policy {policy_name=}')
            resp = iam_helper.create_policy(
                policy_template=policy,
                policy_name=policy_name,
            )
            iam_policies.append(resp.get('Policy'))
    yield iam_policies
    if iam_policies:
        for policy in iam_policies:
            try:
                iam_helper.delete_policy(policy['Arn'])
            except Exception as e:
                logger.error(f"Failed to delete policy {policy['Arn']}: {e}")


@pytest.fixture(scope="function")
def iam_role(aws_account, iam_policies):
    """Fixture to create an IAM role for testing.

    This fixture creates an IAM role and attaches the specified policies to it.

    Args:
        aws_account: AWS account fixture
        iam_policies: List of IAM policies to attach to the role

    Yields:
        dict: Created IAM role information

    Cleanup:
        Detaches policies and deletes the role after the test
    """
    iam_helper = IAMHelper(aws_credentials=aws_account.credentials)
    json_file_path = os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/iam_role_trust.json'))
    role = None
    role_name = f'fortiqa_{random_id}'
    try:
        with open(json_file_path, 'r') as role_trust_file:
            role_trust_json = json.load(role_trust_file)
            resp = iam_helper.create_role(
                role_name=role_name,
                assume_role_policy_document=role_trust_json,
            )
            role = resp.get('Role')
            for iam_policy in iam_policies:
                iam_helper.attach_policy_to_role(
                    role_name=role['RoleName'],
                    policy_arn=iam_policy.get('Arn')
                )
            # We were getting AccessDenied when assuming role immediately after creating it.
            time.sleep(10)
            yield role
    finally:
        if role:
            logger.warning(f'Detaching policies from {role["RoleName"]=}')
            for iam_policy in iam_policies:
                resp = iam_helper.client.detach_role_policy(
                    RoleName=role['RoleName'],
                    PolicyArn=iam_policy.get('Arn')
                )
                print(f'{resp=}')
            logger.warning(f'Deleting {role["RoleName"]=}')
            iam_helper.delete_role(role_name=role.get('RoleName'))


@pytest.fixture(scope="function")
def active_session(iam_role, aws_account, integration_type):
    """Fixture to create an active AWS session.

    This fixture creates an active session by assuming the IAM role and preparing
    the payload with the session credentials.

    Args:
        iam_role: IAM role fixture
        aws_account: AWS account fixture
        integration_type: Type of integration to test

    Yields:
        dict: Payload containing session credentials and integration type
    """
    sts_helper = STSHelper(aws_credentials=aws_account.credentials)
    resp = sts_helper.assume_role(role_arn=iam_role['Arn'], duration=3600)
    creds = resp['Credentials']
    with open(aws_deployment_payload_json_file, 'r') as file:
        payload = json.load(file)
    payload['data']['access_key_id'] = creds['AccessKeyId']
    payload['data']['secret_access_key'] = creds['SecretAccessKey']
    payload['data']['session_token'] = creds['SessionToken']
    # Parametrize integration type
    integration_type = integration_type.split(',')
    payload['integrations'] = integration_type
    logger.info(f"Created new session for iam_role: {iam_role['Arn']}")
    yield payload


@pytest.fixture(scope="function")
def expired_session(iam_role, aws_account):
    """Fixture to create an expired AWS session.

    This fixture creates a session that will be expired by the time it's used,
    useful for testing error handling of expired credentials.

    Args:
        iam_role: IAM role fixture
        aws_account: AWS account fixture

    Yields:
        dict: Payload containing expired session credentials
    """
    sts_helper = STSHelper(aws_credentials=aws_account.credentials)
    resp = sts_helper.assume_role(role_arn=iam_role['Arn'], duration=900)
    time.sleep(1000)
    creds = resp['Credentials']
    with open(aws_deployment_payload_json_file, 'r') as file:
        payload = json.load(file)
    payload['data']['access_key_id'] = creds['AccessKeyId']
    payload['data']['secret_access_key'] = creds['SecretAccessKey']
    payload['data']['session_token'] = creds['SessionToken']
    yield payload


@pytest.fixture(scope="function")
def aws_integration_context(api_v1_client, active_session):
    """Fixture that provides an AWS integration context and handles cleanup.

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        active_session: Fixture that creates a valid session for an IAM role

    Yields:
        AWSIntegrationContext: Context object containing the deployment client and deployment information

    Cleanup:
        Deletes the deployment after the test
    """
    try:
        # Create the context with the deployment client
        context = AWSIntegrationContext(
            deployment_client=Deployments(api_v1_client),
            active_session=active_session
        )

        yield context  # Provide the context to the test

    finally:
        # Cleanup after test
        if context.deployment_id and context.workspace_ids:
            resp = context.deployment_client.pull_integration(deployment_id=context.deployment_id)
            if resp['status'] == 'rolled-back' and all(
                    integration['status'] == 'rolled-back' for integration in resp['integrations']):
                logger.info(f"Deployment {context.deployment_id} has already been cleaned up.")
                return
            try:
                delete_payload = json.load(open(aws_delete_deployment_json_file, 'r'))
                delete_payload['data'].update({
                    'access_key_id': active_session['data']['access_key_id'],
                    'secret_access_key': active_session['data']['secret_access_key'],
                    'session_token': active_session['data']['session_token'],
                    'region': active_session['data']['region']
                })
                delete_payload['workspace_ids'] = context.workspace_ids

                logger.info(f"Cleaning up deployment {context.deployment_id}")
                resp = context.deployment_client.delete_integration(
                    deployment_id=context.deployment_id,
                    payload=delete_payload
                )
                assert resp.status_code == 200, f'Failed to delete integration {context.deployment_id} resp: {resp.text}'

                # Get delete status
                delete_data = context.deployment_client.get_sse(channel=context.deployment_id)
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
        else:
            if not context.deployment_id:
                logger.error("No deployment ID found in context")
            if not context.workspace_ids:
                logger.error("No workspace IDs found in context")


@pytest.fixture(scope="function")
def azure_creds(request, azure_account):
    """Parameterized fixture for Azure credentials with different privilege levels.

    Args:
        request: pytest request object containing the parameter
        azure_account: fixture providing valid Azure credentials

    Returns:
        AzureAccountSettings: Azure credentials with specified privilege level
    """
    scenario = getattr(request, "param", "valid")

    if scenario == "valid":
        return azure_account

    # Load test credentials from yaml
    test_creds_file = os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/azure_test_creds.yaml'))

    with open(test_creds_file) as f:
        test_creds = yaml.safe_load(f)

    if scenario not in test_creds:
        raise ValueError(f"Unknown credential scenario: {scenario}")

    creds = test_creds[scenario]
    return AzureAccountSettings(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
        subscription_id=creds["subscription_id"]
    )


@pytest.fixture(scope="function")
def azure_integration_context(api_v1_client, azure_creds, azure_integration_type):
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
    azure_integration_type = azure_integration_type.split(',')
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


@pytest.fixture(scope="function")
def gcp_creds(gcp_service_account):
    """Fixture to provide GCP credentials for integration testing.

    This fixture creates a temporary file with the service account credentials,
    generates an access token, and returns a dictionary containing the necessary
    GCP credentials for deployment.

    Args:
        gcp_service_account: fixture providing valid GCP service account details

    Returns:
        dict: Dictionary containing GCP credentials with the following keys:
            - access_token (str): GCP access token for authentication
            - project_id (str): GCP project ID
            - org_id (str): GCP organization ID
    """
    # dump the GCP service account details to a temp file and pass it to the function
    with tempfile.NamedTemporaryFile(mode='w+b', delete=True) as f:
        f.write(json.dumps(asdict(gcp_service_account), indent=4).encode('utf-8'))
        f.flush()
        access_token = get_service_account_token(f.name)
        return {
            'access_token': access_token,
            'project_id': gcp_service_account.project_id,
            'org_id': gcp_service_account.org_id,
        }


@pytest.fixture(scope="function")
def gcp_integration_context(api_v1_client, gcp_creds, gcp_integration_type):
    """
    Fixture that provides a GCP integration context and handles cleanup.

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        gcp_creds: GCP credentials for the service account
        gcp_integration_type: Type of GCP integration to test
    Yields:
        GCPIntegrationContext: Context object containing the deployment client and deployment information

    Cleanup:
        Deletes the deployment after the test
    """
    # Create deployment client
    deployment_client = Deployments(api_v1_client)

    gcp_deploy_payload = json.load(open(gcp_deploy_payload_json_file, 'r'))
    gcp_integration_type = gcp_integration_type.split(',')
    gcp_deploy_payload['integrations'] = gcp_integration_type
    gcp_deploy_payload['data'].update({
        'access_token': gcp_creds['access_token'],
        'project_id': gcp_creds['project_id'],
        'org_id': gcp_creds['org_id'],
    })
    logging.info({'gcp_deploy_payload': gcp_deploy_payload})
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
                    'access_token': gcp_creds['access_token'],
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
