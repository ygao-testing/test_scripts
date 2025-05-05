import os
import json
import logging
import pytest
from fortiqa.libs.lw.apiv1.api_client.deployments.deployments import Deployments

logger = logging.getLogger(__name__)

delete_deployment_json_file = os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/delete_deployment.json'))

agentless_allregions = [
  "ap-south-1",
  "eu-north-1",
  "eu-west-3",
  "eu-west-2",
  "eu-west-1",
  "ap-northeast-3",
  "ap-northeast-2",
  "ap-northeast-1",
  "ca-central-1",
  "sa-east-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "eu-central-1",
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2"
]


def required_permissions() -> set:
    """Get the set of required AWS permissions from policy files.

    Returns:
        set: A set of required AWS permissions
    """
    policy_json_files = [
        os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/policies/configuration.json')),
        os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/policies/cloudtrail.json')),
        os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/policies/agentless.json')),
    ]
    permission_set: set[str] = set()
    for json_file_path in policy_json_files:
        with open(json_file_path, 'r') as policy_file:
            policy = json.load(policy_file)
            permission_set = permission_set.union(set(policy['Statement'][0]['Action']))
    return permission_set


class TestAwsDiscovery:

    def is_help_message_in_checks(self, checks: list, message: str):
        found = False
        for check in checks:
            if message in check['HelpMessage']:
                found = True
        return found

    def get_integration_by_id(self, integration_list: list, integration_id: str) -> dict | None:
        for intg in integration_list:
            if intg['ID'] == integration_id:
                return intg
        return None

    @pytest.mark.parametrize('integration_type', ['aws_cloudtrail', 'aws_config', 'aws_agentless'])
    def test_successful_aws_discovery(self, api_v1_client, active_session, aws_account):
        """
        Verify that AWS discovery works as expected when given a valid AWS account.

        Given: API v1 client to interact with the Lacework.
        When: Running discovery with valid AWS account.
        Then: All integrations should be successful and finished.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework.
            active_session: Fixture that creates a valid session for an IAM role.
            aws_account: Fixture that creates a valid AWS account.
        """
        deployment_client = Deployments(api_v1_client)
        channel = deployment_client.generate_channel_id()

        # Log discovery request details
        logger.info(f"Starting discovery for integration types: {active_session['integrations']}")
        logger.debug(f"Discovery payload:\n{json.dumps(active_session, indent=4)}")

        # Run discovery
        resp = deployment_client.run_discovery(payload=active_session, channel=channel)
        logger.info(f"Discovery request status: {resp.status_code}")
        logger.debug(f"Discovery response:\n{resp.text}")

        # Verify discovery response
        assert resp.status_code == 200, (
            f"Discovery request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(active_session, indent=4)}"
        )

        # Get SSE data
        data = deployment_client.get_sse(channel=channel)
        logger.debug(f'SSE: {data=}')
        integrations = data['results']['integrations']
        logger.info(f"Found {len(integrations)} integrations in response")

        # Check each integration
        for discovery_type in active_session['integrations']:
            integration = self.get_integration_by_id(integrations, discovery_type)

            # Verify integration exists
            assert integration is not None, (
                f"Integration {discovery_type} not found in response.\n"
                f"Available integrations: {[i.get('ID') for i in integrations]}\n"
                f"Full response: {json.dumps(data, indent=4)}"
            )

            # Verify integration state
            assert integration['State'] == 'Passed', (
                f"Integration {discovery_type} failed:\n"
                f"State: {integration['State']}\n"
                f"Checks:\n{json.dumps(integration.get('Checks', []), indent=4)}\n"
                f"Messages:\n{json.dumps(data.get('messages', []), indent=4)}\n"
                f"Integration details:\n{json.dumps(integration, indent=4)}"
            )

    @pytest.mark.slow_self_deployment_test
    @pytest.mark.parametrize('integration_type', ['aws_cloudtrail,aws_agentless,aws_config'])
    def test_aws_discovery_error_with_expired_session(self, api_v1_client, expired_session):
        """
        Verify that AWS discovery fails with an expired session.

        Given: API v1 client.
        When: Run discovery with expired session.
        Then: Discovery should fail with an error message.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework.
            expired_session: Fixture that creates an expired session.
        """
        deployment_client = Deployments(api_v1_client)
        channel = deployment_client.generate_channel_id()

        # Log test start
        logger.info("Starting expired session test")
        logger.debug(f"Expired session payload:\n{json.dumps(expired_session, indent=4)}")

        # Run discovery with expired session
        resp = deployment_client.run_discovery(payload=expired_session, channel=channel)
        logger.info(f"Discovery request status: {resp.status_code}")
        logger.debug(f"Discovery response:\n{resp.text}")
        assert resp.status_code == 400, f"Discovery should fail, found status code {resp.status_code}"
        assert "invalid CSP credentials" in resp.text, "Discovery should fail with invalid credentials error. Found: {}".format(resp.text)

    # TODO: Add agentless tests on more and all regions, skip for now because of roll-back failure.
    # (['aws_agentless'], ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']),
    @pytest.mark.parametrize('integration_type,agentless_regions', [
        ('aws_cloudtrail', None),
        ('aws_config', None),
        ('aws_agentless', ['us-east-1']),
    ])
    def test_successful_aws_integration(self, aws_integration_context, integration_type, agentless_regions):
        """
        Verify that AWS integration works as expected.

        Given: API v1 client to interact with the Lacework.
        When: Running integration with valid AWS account.
        Then: All integrations should be successful and finished.

        Args:
            aws_integration_context: Fixture that provides integration context and handles cleanup.
            integration_type: Type of AWS integration to test
            agentless_regions: List of regions for agentless scanning, only used when integration type is aws_agentless
        """
        # Prepare integration payload
        integration_payload = json.loads(json.dumps(aws_integration_context.active_session))
        if 'aws_agentless' in integration_type and agentless_regions:
            integration_payload['data']['agentless_regions'] = agentless_regions
        logger.debug(f"Integration payload:\n{json.dumps(integration_payload, indent=4)}")
        # Run integration
        deployment_client = aws_integration_context.deployment_client
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
        aws_integration_context.deployment_id = deployment_data.get('deployment_id')
        logger.info(f"Deployment ID: {aws_integration_context.deployment_id}")

        integration_data = deployment_client.get_sse(channel=aws_integration_context.deployment_id)

        # Verify integration status
        resp = deployment_client.pull_integration(
            deployment_id=aws_integration_context.deployment_id
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
        aws_integration_context.workspace_ids = workspace_ids
        logger.info(f"pulled integration response:\n{json.dumps(resp, indent=4)}")

    @pytest.mark.skip(reason="temporarily disabled")
    @pytest.mark.parametrize('integration_type', ['aws_cloudtrail'])
    def test_delete_deployment(self, api_v1_client, active_session, aws_account):
        """
        Verify that a deployment is deleted using LW API.

        Given: API v1 client to interact with the Lacework.
        When: Deleting a deployment using LW API.
        Then: The deployment should be deleted.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework.
            active_session: Fixture that creates a valid session for an IAM role.
            aws_account: Fixture that creates a valid AWS account.
        """
        # TODO: Implement this test.
        deployment_client = Deployments(api_v1_client)
        deployment_id = '146'  # TODO: Create deployment dynamically instead of hardcoding

        # Get deployment info
        logger.info(f"Getting deployment info for ID: {deployment_id}")
        resp = deployment_client.get_integration(deployment_id=deployment_id)
        assert resp.status_code == 200, (
            f"Failed to get deployment info. Status: {resp.status_code}\n"
            f"Response: {resp.text}"
        )

        deployment_info = resp.json().get('data', {})
        logger.debug(f"Deployment info:\n{json.dumps(deployment_info, indent=4)}")

        # Verify deployment info structure
        assert 'integrations' in deployment_info, (
            f"Invalid deployment info structure:\n{json.dumps(deployment_info, indent=4)}"
        )

        # Extract workspace IDs
        workspace_ids = []
        for integration in deployment_info['integrations']:
            workspace_id = integration.get('workspace_id')
            if workspace_id:
                workspace_ids.append(workspace_id)
                logger.info(f"Found workspace ID: {workspace_id}")
            else:
                logger.warning(f"Integration missing workspace_id: {json.dumps(integration, indent=4)}")

        assert workspace_ids, (
            "No workspace IDs found in deployment info:\n"
            f"{json.dumps(deployment_info, indent=4)}"
        )
        delete_payload = json.load(open(delete_deployment_json_file, 'r'))
        delete_payload['data']['access_key_id'] = active_session['data']['access_key_id']
        delete_payload['data']['secret_access_key'] = active_session['data']['secret_access_key']
        delete_payload['data']['session_token'] = active_session['data']['session_token']
        delete_payload['data']['region'] = active_session['data']['region']

        # Prepare deletion payload
        delete_payload['workspace_ids'] = workspace_ids
        logger.debug(f"Delete payload:\n{json.dumps(delete_payload, indent=4)}")

        # Delete deployment
        logger.info(f"Deleting deployment {deployment_id}")
        resp = deployment_client.delete_integration(
            deployment_id=deployment_id,
            payload=delete_payload
        )
        logger.info(f"Delete request status: {resp.status_code}")
        logger.debug(f"Delete response:\n{resp.text}")

        assert resp.status_code == 200, (
            f"Deployment deletion failed with status {resp.status_code}\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(delete_payload, indent=4)}"
        )

        # Check deletion status
        resp = deployment_client.pull_integration(deployment_id=deployment_id)

        # Format integration status for logging
        integration_status = []
        for integration in resp.get('integrations', []):
            status_entry = (
                f"Integration: {integration.get('name', 'Unknown')}\n"
                f"  Status: {integration.get('status', 'Unknown')}\n"
                f"  Error: {integration.get('error', 'None')}"
            )
            integration_status.append(status_entry)

        logger.info("Integration deletion status:")
        for status in integration_status:
            logger.info(status)

        # Verify all integrations are deleted
        assert all(
            integration.get('status') == 'rolled-back'
            for integration in resp.get('integrations', [])
        ), (
            "Not all integrations were successfully deleted\n"
            f"Integration status:\n{''.join(integration_status)}\n"
            f"Full response:\n{json.dumps(resp, indent=4)}"
        )

    @pytest.mark.slow_self_deployment_test
    @pytest.mark.parametrize('integration_type', ['aws_cloudtrail,aws_agentless,aws_config'])
    @pytest.mark.parametrize('missing_permission', required_permissions(), indirect=True)
    def test_discovery_fails_with_missing_permission(self, api_v1_client, active_session, missing_permission):
        """
        Verify that AWS discovery fails with an error message when a required permission is missing.

        Given: API v1 client, active session and a missing required permission.
        When: Run discovery with the active session.
        Then: Discovery should fail with an error message mentioning the missing permission.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework.
            active_session: Fixture that creates a valid session for an IAM role.
            missing_permission: Fixture that creates a missing required permission.
        """
        deployment_client = Deployments(api_v1_client)
        channel = deployment_client.generate_channel_id()

        # Log test details
        logger.info(f"Testing discovery with missing permission: {missing_permission}")
        logger.debug(f"Active session payload:\n{json.dumps(active_session, indent=4)}")

        # Run discovery
        resp = deployment_client.run_discovery(payload=active_session, channel=channel)
        logger.info(f"Discovery request status: {resp.status_code}")
        logger.debug(f"Discovery response:\n{resp.text}")

        # Get SSE data
        data = deployment_client.get_sse(channel=channel)
        logger.debug(f"SSE response data:\n{json.dumps(data, indent=4)}")

        # Verify response structure
        assert 'results' in data and 'integrations' in data['results'], (
            f"Invalid response structure:\n{json.dumps(data, indent=4)}"
        )

        integrations = data['results']['integrations']
        aws_config = self.get_integration_by_id(integrations, 'aws_config')
        aws_agentless = self.get_integration_by_id(integrations, 'aws_agentless')
        aws_cloudtrail = self.get_integration_by_id(integrations, 'aws_cloudtrail')

        # Log integration states
        logger.info("Integration states:")
        if aws_config:
            logger.info(f"  AWS Config: {aws_config['State']}")
        if aws_agentless:
            logger.info(f"  AWS Agentless: {aws_agentless['State']}")
        if aws_cloudtrail:
            logger.info(f"  AWS CloudTrail: {aws_cloudtrail['State']}")

        # Verify at least one integration failed
        assert any(
            integration and integration['State'] == 'Failed'
            for integration in [aws_config, aws_agentless, aws_cloudtrail]
        ), (
            "Expected at least one integration to fail due to missing permission\n"
            f"AWS Config state: {aws_config['State'] if aws_config else 'Not found'}\n"
            f"AWS Agentless state: {aws_agentless['State'] if aws_agentless else 'Not found'}\n"
            f"AWS CloudTrail state: {aws_cloudtrail['State'] if aws_cloudtrail else 'Not found'}\n"
            f"Full response:\n{json.dumps(data, indent=4)}"
        )

        # Check for missing permission message
        error_found = False
        error_details = []

        for integration_name, integration in [
            ("AWS Config", aws_config),
            ("AWS Agentless", aws_agentless),
            ("AWS CloudTrail", aws_cloudtrail)
        ]:
            if integration and self.is_help_message_in_checks(
                integration['Checks'],
                f'Required permission missing {missing_permission}'
            ):
                error_found = True
                logger.info(f"Found missing permission error in {integration_name}")
            elif integration:
                error_details.append(
                    f"{integration_name} checks:\n"
                    f"{json.dumps(integration.get('Checks', []), indent=4)}"
                )

        assert error_found, (
            f"Missing permission '{missing_permission}' not found in any integration checks\n"
            f"Integration check details:\n{''.join(error_details)}\n"
            f"Messages:\n{json.dumps(data.get('messages', []), indent=4)}"
        )
