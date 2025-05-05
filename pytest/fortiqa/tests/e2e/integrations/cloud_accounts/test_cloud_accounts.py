import json
import time
import logging
import pytest
import string
import random

from fortiqa.libs.lw.apiv2.helpers.cloud_account_helper import CloudAccountHelper
from fortiqa.libs.lw.apiv2.helpers.template_file_helper import TemplateFileHelper
from fortiqa.libs.aws.cloudformation import CloudformationHelper
from fortiqa.tests.e2e.integrations.cloud_accounts.helpers import generate_and_run_aws_eks_audit_cft, generate_and_run_aws_config_cft


logger = logging.getLogger(__name__)


@pytest.mark.cloud_integrations
class TestCloudAccountIntegrations:

    def _create_cloud_account_payload(self, aws_account_id: str):
        return {
            'name': f'aws_cfg_{aws_account_id}',
            'type': 'AwsCfg',
            'enabled': 1,
            'data': {
                'awsAccountId': f'{aws_account_id}',
                'crossAccountCredentials': {
                    'externalId': f'lweid:aws:v2:fortiqa:{aws_account_id}:7D4FCFE9F8',  # noqa : E231
                    'roleArn': f'arn:aws:iam::{aws_account_id}:role/non-existent-role',  # noqa : E231
                }
            }
        }

    @pytest.fixture
    def create_aws_cloud_config_integration(self, api_v2_client, aws_account):
        """Fixture to create AWS Configuration integration using CloudFormation stack."""
        stack_id = generate_and_run_aws_config_cft(api_v2_client, aws_account.credentials)
        yield stack_id
        CloudformationHelper(aws_credentials=aws_account.credentials).delete_stack(stack_id)
        CloudformationHelper(aws_credentials=aws_account.credentials).wait_for_delete_complete(stack_id)
        time.sleep(10)

    def test_rerun_aws_config_cloudformation_expect_rollback(self, api_v2_client, create_aws_cloud_config_integration, aws_account):
        """Verify CloudFormation stack is rolled back if ran the second time.

        Given: Onboarded AWS account for testing.
        When: Run CloudFormation stack to onboard the same AWS account again.
        Then: CloudFormation stack should be rolled back.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            create_aws_cloud_config_integration: AWS configuration integration.
        """
        resp = TemplateFileHelper(api_v2_client).get_aws_config_template()
        assert resp.status_code == 200
        template = resp.text
        stack_name = 'fortiqa-aws-cfg-' + ''.join(random.choice(string.ascii_uppercase) for _ in range(4))
        stack_id = None
        try:
            stack_id = CloudformationHelper(aws_credentials=aws_account.credentials).create_stack(
                stack_name=stack_name,
                template_body=json.dumps(json.loads(template)),
                capabilities=['CAPABILITY_NAMED_IAM'])
            CloudformationHelper(aws_credentials=aws_account.credentials).wait_for_rollback_complete(stack_id)
        finally:
            if stack_id:
                CloudformationHelper(aws_credentials=aws_account.credentials).delete_stack(stack_id)

    def test_integrate_eks_audit_with_cloudformation(self, api_v2_client, aws_account):
        """Verify CloudFormation stack for EKS Audit Log integration creates successfully.

        Given: API v2 client to interact with Lacework.
        When: Downlaod and run cloudformation template to integrate EKS audit logs.
        Then: CFT stack should have 'CREATE_COMPLETE' status.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
        """
        stack_id = None
        try:
            stack_id = generate_and_run_aws_eks_audit_cft(api_v2_client, aws_account.credentials)
        finally:
            if stack_id:
                CloudformationHelper(aws_credentials=aws_account.credentials).delete_stack(stack_id)

    def test_integrate_aws_config_with_cloudformation(self, api_v2_client, aws_account):
        """Verify CloudFormation stack for AWS Configuration integration creates successfully.

        Given: API v2 client to interact with Lacework.
        When: Downlaod and run cloudformation template for AWS Configuration integration.
        Then: CFT stack should have 'CREATE_COMPLETE' status.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
        """
        stack_id = None
        try:
            stack_id = generate_and_run_aws_config_cft(api_v2_client, aws_account.credentials)
        finally:
            if stack_id:
                CloudformationHelper(aws_credentials=aws_account.credentials).delete_stack(stack_id)

    def test_create_with_invalid_external_id_expect_400(self, api_v2_client):
        """Verify API response 400 when creating AWS Configuration integration with invalid external id.

        Given: API v2 client to interact with Lacework.
        When: Try to create AWS integration using external ID with invalid format in payload.
        Then: API response should have status_code=400 and message='Validate the specified External id.'.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
        """
        payload = self._create_cloud_account_payload('112233445566')
        payload['data']['crossAccountCredentials']['externalId'] = 'lweid:aws:222:fortiqa:112233445566:7D4FCFE9F8'
        resp = CloudAccountHelper(api_v2_client).create_aws_cfg_cloud_account(payload)
        api_data = json.loads(resp.text)
        assert resp.status_code == 400, f'Received {resp.status_code} instead of expected 400'
        assert 'message' in api_data
        assert api_data['message'] == 'Validate the specified External id.'

    def test_create_with_invalid_arn_expect_400(self, api_v2_client):
        """Verify API response 400 when creating AWS Configuration integration with non-existent role arn.

        Given: API v2 client to interact with Lacework.
        When: Try to create AWS integration using non-existent role arn in payload.
        Then: API response should have status_code=400 and message='Validate the specified aws Role arn.'.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
        """
        payload = self._create_cloud_account_payload('223344556677')
        payload['data']['crossAccountCredentials']['roleArn'] = 'arn:aws:iam::223344556677:role/non-existent-role'
        resp = CloudAccountHelper(api_v2_client).create_aws_cfg_cloud_account(payload)
        api_data = json.loads(resp.text)
        assert resp.status_code == 400, f'Received {resp.status_code} instead of expected 400'
        assert 'message' in api_data
        assert api_data['message'] == 'Validate the specified aws Role arn.'

    def test_tf_cloud_accounts(self, api_v2_client, tf_cloud_accounts: list):
        """Verify cloud account integrations deployed using lacework TF provider are returned by LW API.

        Given: List of cloud account integrations pre-deployed with terraform.
        When: Listing cloud account integrations using LW API.
        Then: Cloud accounts deployed by terraform should be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            tf_cloud_accounts: list of cloud account integrations deployed with terraform.
        """
        resp = CloudAccountHelper(api_v2_client).get_all_cloud_accounts()
        accounts_from_api = json.loads(resp.text)
        not_found = []
        for account in tf_cloud_accounts:
            found = False
            for acc in accounts_from_api:
                if account['name'] == acc['name'] and \
                    account['type'] == acc['type'] and \
                   account['intg_guid'] == acc['intgGuid']:
                    found = True
            if not found:
                not_found.append(account)
        assert len(not_found) == 0, f'Accounts {not_found} were not in API response {accounts_from_api}'
