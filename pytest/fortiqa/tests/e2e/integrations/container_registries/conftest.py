import json
import os
import time
import pytest
import logging
import random
import string

from fortiqa.libs.aws.iam import IAMHelper
from fortiqa.libs.aws.iam_user import IAMUserHelper
from fortiqa.libs.aws.sts import STSHelper
from fortiqa.tests import settings


logger = logging.getLogger(__name__)


random_id = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))


@pytest.fixture(scope="function")
def aws_cross_account_role(aws_account):
    """Fixture to create a cross-account IAM role for Lacework platform.

    This fixture creates an IAM role that trusts the Lacework platform account
    and has read-only access to Amazon ECR.

    Args:
        aws_account: AWS account fixture

    Yields:
        tuple: (dict, str) Tuple containing:
            - Created IAM role information
            - External ID used for the role

    Cleanup:
        Detaches policies and deletes the role after the test
    """
    iam_helper = IAMHelper(aws_credentials=aws_account.credentials)
    role = None
    role_name = f'fortiqa-lacework-{random_id}'

    # Generate external ID
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    external_id = f"lweid:aws:v2:{settings.app.customer['account_name']}:{settings.app.aws_account.aws_account_id}:{random_string}"

    # Create trust policy
    # trust_policy = {
    #     "Version": "2012-10-17",
    #     "Statement": [
    #         {
    #             "Effect": "Allow",
    #             "Principal": {
    #                 "AWS": [
    #                     "arn:aws:iam::434813966438:role/lacework-platform",
    #                     f"arn:aws:iam::{settings.app.aws_account.aws_account_id}:user/self_deployment_test_zq"
    #                 ]
    #             },
    #             "Action": "sts:AssumeRole",
    #             "Condition": {
    #                 "StringEquals": {
    #                     "sts:ExternalId": external_id
    #                 }
    #             }
    #         }
    #     ]
    # }
    json_file_path = os.path.abspath(os.path.expanduser('./e2e/integrations/cloud_accounts/data/iam_role_trust.json'))

    try:
        # Create role with trust policy
        with open(json_file_path, 'r') as role_trust_file:
            trust_policy = json.load(role_trust_file)

        resp = iam_helper.create_role(
            role_name=role_name,
            assume_role_policy_document=trust_policy,
        )
        role = resp.get('Role')

        # Attach ECR read-only policy
        iam_helper.attach_policy_to_role(
            role_name=role['RoleName'],
            policy_arn='arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly'
        )

        # Wait for role to propagate
        time.sleep(10)
        yield role, external_id

    finally:
        if role:
            logger.warning(f'Cleaning up role {role["RoleName"]}')
            try:
                # Detach policy
                iam_helper.client.detach_role_policy(
                    RoleName=role['RoleName'],
                    PolicyArn='arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly'
                )
                # Delete role
                iam_helper.delete_role(role['RoleName'])
            except Exception as e:
                logger.error(f"Failed to clean up role {role['RoleName']}: {e}")


@pytest.fixture(scope="function")
def ecr_onboarding_iam_payload(aws_cross_account_role, aws_account):
    """Fixture to create payload for ECR onboarding.

    This fixture assumes the IAM role and prepares
    the payload with the credentials.

    Args:
        aws_cross_account_role: AWS cross account role fixture (tuple of role and external ID)
        aws_account: AWS account fixture
        integration_type: Type of integration to test

    Yields:
        dict: Payload containing session credentials and integration type
    """
    role, external_id = aws_cross_account_role
    sts_helper = STSHelper(aws_credentials=aws_account.credentials)
    sts_helper.assume_role(role_arn=role['Arn'], duration=3600)

    payload_json_file = os.path.abspath(os.path.expanduser('./e2e/integrations/container_registries/data/ecr_onboarding_iam_payload.json'))

    with open(payload_json_file, 'r') as file:
        payload = json.load(file)

    # TODO: REGISTRY_DOMAIN is hardcoded in the payload for now
    payload['DATA']['CROSS_ACCOUNT_CREDENTIALS']['EXTERNAL_ID'] = external_id
    payload['DATA']['CROSS_ACCOUNT_CREDENTIALS']['ROLE_ARN'] = role['Arn']

    logger.info(f"Created ECR onboarding payload with iam_role: {role['Arn']}")
    yield payload


@pytest.fixture(scope="function")
def ecr_onboarding_access_key_payload(aws_account):
    """Fixture to create payload for ECR onboarding.

    This fixture assumes the IAM role and prepares
    the payload with the credentials.

    Args:
        aws_account: AWS account fixture

    Yields:
        dict: Payload containing session credentials and integration type
    """
    iam_user_helper = IAMUserHelper(aws_credentials=aws_account.credentials)
    test_user_name = "temp_ecr_onboarding_user"
    test_tags = {"Environment": "test_ecr_onboarding", "Project": "fortiqa"}

    user = iam_user_helper.create_iam_user(
        user_name=test_user_name,
        tags=test_tags
    )
    assert user.user_name == test_user_name
    assert user.tags == test_tags
    assert user.access_key_id is not None
    assert user.secret_access_key is not None

    iam_user_helper.attach_policy_to_user(user_name=user.user_name, policy_name='AmazonEC2ContainerRegistryReadOnly')
    time.sleep(10)

    payload_json_file = os.path.abspath(os.path.expanduser('./e2e/integrations/container_registries/data/ecr_onboarding_access_key_payload.json'))

    with open(payload_json_file, 'r') as file:
        payload = json.load(file)

    payload['DATA']['ACCESS_KEY_CREDENTIALS']['ACCESS_KEY_ID'] = user.access_key_id
    payload['DATA']['ACCESS_KEY_CREDENTIALS']['SECRET_ACCESS_KEY'] = user.secret_access_key

    yield payload

    delete_success = iam_user_helper.delete_iam_user(test_user_name)
    assert delete_success
    logger.info(f"Successfully deleted IAM user: {test_user_name}")
