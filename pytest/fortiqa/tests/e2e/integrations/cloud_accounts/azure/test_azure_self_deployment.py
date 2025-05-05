import os
import json
import logging
import pytest

logger = logging.getLogger(__name__)


class TestAzureDiscovery:

    @pytest.mark.parametrize('azure_integration_type', [
        "azure_activity_log,azure_config"
    ])
    @pytest.mark.parametrize("azure_creds", [
        "valid"
    ], indirect=True)
    def test_successful_azure_integration(self, azure_integration_context, azure_integration_type):
        """
        Verify that Azure integration works as expected.

        Given: API v1 client to interact with the Lacework.
        When: Running integration with valid Azure account.
        Then: All integrations should be successful and finished.

        Args:
            azure_integration_context: Fixture that provides integration context and handles cleanup.
            azure_integration_type: Type of Azure integration to test
        """
        # Prepare integration payload
        integration_payload = json.loads(json.dumps(azure_integration_context.deployment_payload))

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

    @pytest.mark.parametrize('azure_integration_type', [
        "azure_activity_log,azure_config"
    ])
    @pytest.mark.parametrize("azure_creds", [
        "missing_app_admin_role",
        "missing_privileged_admin_role",
    ], indirect=True)
    def test_azure_integration_with_missing_privileges(self, azure_integration_context, azure_integration_type):
        """
        Verify that Azure integration fails with an error message when a required permission is missing.

        Given: API v1 client, active session and a missing required permission.
        When: Run integration with the active session.
        Then: Integration should fail with an error message mentioning the missing permission.

        Args:
            azure_integration_context: Fixture that provides integration context and handles cleanup.
            azure_integration_type: Type of Azure integration to test
        """
        # Prepare integration payload
        integration_payload = json.loads(json.dumps(azure_integration_context.deployment_payload))

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
        deployment_data = resp.json().get('data', {})
        azure_integration_context.deployment_id = deployment_data.get('deployment_id')
        logger.info(f"Deployment ID: {azure_integration_context.deployment_id}")

        integration_data = deployment_client.get_sse(channel=azure_integration_context.deployment_id, timeout=3600)

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
            resp['status'] == 'failed' and
            all(integration['status'] == 'failed' for integration in resp['integrations'])
        ), (
            'Integration should have failed:'
            f"{resp['status']=} "
            f"{integration_logs=} "
            f"SSE message: {integration_data['messages']}"
        )

        azure_integration_context.xfail = True

    @pytest.mark.parametrize('azure_integration_type', [
        "azure_activity_log,azure_config"
    ])
    @pytest.mark.parametrize("azure_creds", [
        "invalid_id_format",
    ], indirect=True)
    def test_azure_integration_with_invalid_creds(self, azure_integration_context, azure_integration_type):
        """
        Verify that Azure integration fails with an error message when a required permission is missing.

        Given: API v1 client, active session and a missing required permission.
        When: Run integration with the active session.
        Then: Integration should fail with an error message mentioning the missing permission.

        Args:
            azure_integration_context: Fixture that provides integration context and handles cleanup.
            azure_integration_type: Type of Azure integration to test
        """
        # Prepare integration payload
        integration_payload = json.loads(json.dumps(azure_integration_context.deployment_payload))

        # Run integration
        deployment_client = azure_integration_context.deployment_client
        resp = deployment_client.run_integration(
            payload=integration_payload
        )
        logger.info(f"Integration request status: {resp.status_code}")
        logger.debug(f"Integration response:\n{resp.text}")

        # Verify integration response
        assert resp.status_code == 400, (
            f"Integration request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(integration_payload, indent=4)}"
        )
        assert "invalid CSP credentials" in resp.text, "Integration should fail with invalid credentials error. Found: {}".format(resp.text)
        azure_integration_context.xfail = True
