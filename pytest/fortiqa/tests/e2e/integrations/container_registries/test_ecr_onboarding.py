import json
import logging
from fortiqa.libs.lw.apiv1.api_client.ecr_onboarding.onboarding import ECROnboarding

logger = logging.getLogger(__name__)


class TestAwsECROnboarding:

    def test_successful_ecr_onboarding_using_IAM(self, api_v1_client, ecr_onboarding_iam_payload):
        """
        Verify that ECR onboarding works as expected using IAM role.

        Given: API v1 client to interact with the Lacework.
        When: Running ECR onboarding using IAM role.
        Then: All integrations should be successful and finished.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework.
            ecr_onboarding_iam_payload: Fixture that creates payload for ECR onboarding using IAM role.
        """
        onboarding_client = ECROnboarding(api_v1_client)

        # Log ecr onboarding request details
        logger.debug(f"ecr onboarding payload:\n{json.dumps(ecr_onboarding_iam_payload, indent=4)}")

        # Run discovery
        resp = onboarding_client.run_onboarding(payload=ecr_onboarding_iam_payload)
        logger.info(f"Onboarding request status: {resp.status_code}")
        logger.debug(f"Onboarding response:\n{resp.text}")

        # Verify ecr onboarding response
        assert resp.status_code == 201, (
            f"Onboarding request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(ecr_onboarding_iam_payload, indent=4)}"
        )

        intg_guid = resp.json()['data'][0]['INTG_GUID']
        # check onboarding status
        data = onboarding_client.pull_ecr_onboarding(id=intg_guid)
        logger.debug(f"pull ECR onboarding status:\n{json.dumps(data, indent=4)}")

        onboarding_status = data['STATE']
        assert onboarding_status['ok'], (
            f"ECR onboarding request succeeded but integration failed. Status: {json.dumps(onboarding_status, indent=4)}\n"
        )

        resp = onboarding_client.delete_ecr_onboarding(id=intg_guid)

        assert resp.status_code == 200, (
            f"Delete onboarding request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(ecr_onboarding_iam_payload, indent=4)}"
        )

    def test_successful_ecr_onboarding_using_access_key(self, api_v1_client, ecr_onboarding_access_key_payload):
        """
        Verify that ECR onboarding works as expected using access key.

        Given: API v1 client to interact with the Lacework.
        When: Running ECR onboarding using access key.
        Then: All integrations should be successful and finished.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework.
            ecr_onboarding_access_key_payload: Fixture that creates payload for ECR onboarding using access key.
        """
        onboarding_client = ECROnboarding(api_v1_client)

        # Log ecr onboarding request details
        logger.debug(f"ecr onboarding payload:\n{json.dumps(ecr_onboarding_access_key_payload, indent=4)}")
        # Run discovery
        resp = onboarding_client.run_onboarding(payload=ecr_onboarding_access_key_payload)
        logger.info(f"Onboarding request status: {resp.status_code}")
        logger.debug(f"Onboarding response:\n{resp.text}")

        # Verify ecr onboarding response
        assert resp.status_code == 201, (
            f"Onboarding request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(ecr_onboarding_access_key_payload, indent=4)}"
        )

        intg_guid = resp.json()['data'][0]['INTG_GUID']
        # check onboarding status
        data = onboarding_client.pull_ecr_onboarding(id=intg_guid)
        logger.debug(f"pull ECR onboarding status:\n{json.dumps(data, indent=4)}")

        onboarding_status = data['STATE']
        assert onboarding_status['ok'], (
            f"ECR onboarding request succeeded but integration failed. Status: {json.dumps(onboarding_status, indent=4)}\n"
        )

        resp = onboarding_client.delete_ecr_onboarding(id=intg_guid)

        assert resp.status_code == 200, (
            f"Delete onboarding request failed with status {resp.status_code}:\n"
            f"Response: {resp.text}\n"
            f"Request payload: {json.dumps(ecr_onboarding_access_key_payload, indent=4)}"
        )
