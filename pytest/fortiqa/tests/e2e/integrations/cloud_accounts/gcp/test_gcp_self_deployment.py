import os
import json
import logging
import pytest
import time
logger = logging.getLogger(__name__)


agentless_all_regions = [
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


class TestGCPAutomaticConfiguration:

    def get_integration_by_id(self, integration_list: list, integration_id: str) -> dict | None:
        for intg in integration_list:
            if intg['ID'] == integration_id:
                return intg

    @pytest.mark.parametrize('gcp_integration_type', ['gcp_audit_log', 'gcp_config', 'gcp_agentless'])
    def test_successful_gcp_discovery(self, gcp_integration_context, gcp_integration_type):
        """
        Verify that GCP discovery works as expected when given a valid GCP account.

        Given: API v1 client to interact with the Lacework.
        When: Running discovery with valid GCP account.
        Then: All integrations should be successful and finished.

        Args:
            gcp_integration_context: Fixture that creates a valid session for an IAM role.
            gcp_account: Fixture that creates a valid GCP account.
        """
        deployment_client = gcp_integration_context.deployment_client
        channel = deployment_client.generate_channel_id()
        payload = gcp_integration_context.deployment_payload

        # Log discovery request details
        logger.info(f"Starting discovery for integration types: {gcp_integration_type}")
        logger.debug(f"Discovery payload:\n{json.dumps(payload, indent=4)}")

        # Run discovery
        resp = deployment_client.run_discovery(payload=payload, channel=channel)
        logger.info(f"Discovery request status: {resp.status_code}")
        logger.debug(f"Discovery response:\n{resp.text}")

        # Verify discovery response
        assert resp.status_code == 200, (
            f"Discovery request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(payload, indent=4)}"
        )

        # Get SSE data
        data = deployment_client.get_sse(channel=channel)
        logger.debug(f'SSE: {data=}')
        integrations = data['results']['integrations']
        assert len(integrations) > 0, "No integrations found in response"
        logger.info(f"Found {len(integrations)} integrations in response")

        # Check each integration
        for discovery_type in gcp_integration_type.split(','):
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
        # set roll back xfail because this is only discovery
        gcp_integration_context.xfail = True

    @pytest.mark.parametrize('gcp_integration_type', [
        'gcp_agentless',
        'gcp_audit_log',
        'gcp_config'
    ])
    def test_successful_gcp_integration(self, gcp_integration_context, gcp_integration_type):
        """
        Verify that GCP integration works as expected.

        Given: API v1 client to interact with the Lacework.
        When: Running integration with valid GCP account.
        Then: All integrations should be successful and finished.

        Args:
            gcp_integration_context: Fixture that provides integration context and handles cleanup.
            gcp_integration_type: Type of GCP integration to test
        """
        # Prepare integration payload
        integration_payload = json.loads(json.dumps(gcp_integration_context.deployment_payload))

        # Run integration
        deployment_client = gcp_integration_context.deployment_client
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
