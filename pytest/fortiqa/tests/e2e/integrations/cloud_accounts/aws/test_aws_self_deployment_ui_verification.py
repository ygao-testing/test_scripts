"""Onboarding AWS self-deployment GUI tests"""
import logging
import random
import pytest
import os
import json

from fortiqa.tests import settings

info = logging.getLogger(__name__).info

integration_ui_mapping = {
    'aws_agentless': 'Agentless Workload Scanning',
    'aws_config': 'Configuration',
    'aws_cloudtrail': 'CloudTrail',
}

# permission removed according to dev team.
xfail_permissions = [
]


def random_missing_permission() -> str:
    """
    Get a random required AWS permission from all policy files (excluding the xfail permissions).

    Returns:
        str: A random required AWS permission
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
    permission_list = list(permission_set)

    # Remove permissions which have issue during the discovery stage (Discovery pass even without required permission)
    # Jira ticket: https://lacework.atlassian.net/browse/GROW-2995
    for permission in xfail_permissions:
        permission_list.remove(permission)
    return random.choice(permission_list)


@pytest.mark.ui
@pytest.mark.download
@pytest.mark.parametrize('integration_type', ['aws_agentless', 'aws_config', 'aws_cloudtrail'])
@pytest.mark.parametrize("delete_files", [{"prefix": "tf-files", "suffix": "gz"}], indirect=True)
def test_successful_aws_integration_ui(ui, aws_integration_context, integration_type, delete_files):
    """
    Verify on GUI page that AWS discovery works as expected when given a valid AWS role.

    Given: UI session that sign in to Lacework portal & Valid IAM role.
    When: Run discovery with valid AWS role.
    Then: All integrations should be successful and finished, info on the UI should be correct.

    Args:
        ui: Fixture that open that UI session which sign in to Lacework portal.
        active_session: Fixture that creates a valid session for an IAM role.
        integration_type: Parametrize data for different integration type.

    Oriole Test Cases:
        1204367 [Discovery] Discovery success with the valid credentials provided
        1204368 [Discovery] Show "Ready to integrate" if discovery success
        1204369 [Discovery] Show correct "Ready to integrate" if discovery success
        1204370 [Discovery] Show correct "Caller Identity"
        1204371 [Discovery] Show correct "AWS Account"
        1204372 [Discovery] Show correct "AWS Organization Access"
        1204373 [Discovery] Show correct "CloudTrail Name"
        1204374 [Discovery] Show correct "EKS Clusters"
        1204375 [Discovery] Show correct "Enabled Regions"
        1204376 [Discovery] "Back" button is enabled
        1204377 [Discovery] "Integrate" button is enabled
        1204378 [Integrate] Initiate integration process by clicking "Integrate" button
        1204379 [Integrate] Show SSE logs during integration process
        1204380 [Integrate] Integration success with the valid credentials provided
        1204381 [Integrate] Show integration success text if integration success
        1204382 [Integrate] Show correct "Account ID"
        1204383 [Integrate] Show correct "Account Principal"
1        1204390 [Integrate] Download TF file by clicking "Download Terraform files"
        1204384 [Rollback] Initiate Rollback process by clicking "Rollback" button and fill the credentials form
        1204385 [Rollback] Show SSE logs during Rollback process
        1204386 [Rollback] Rollback success with the valid credentials provided
        1204387 [Rollback] Show rollback success text if rollback success
        1204388 [Rollback] Show correct "Account ID"
        1204389 [Rollback] Show correct "Account Principal"
    """
    active_session_data = json.loads(json.dumps(aws_integration_context.active_session))["data"]
    integration_data = {
        "integration_method": integration_ui_mapping[integration_type],
        "access_key_id": active_session_data["access_key_id"],
        "secret_access_key": active_session_data["secret_access_key"],
        "session_token": active_session_data["session_token"],
        "default_region": active_session_data["region"],
    }
    ui.settings_onboarding.aws_integration(integration_data, aws_integration_context,
                                           roll_back=settings.app.customer["account_name"] != "fortiqa")


@pytest.mark.ui
@pytest.mark.parametrize('integration_type', [random.choice(['aws_agentless', 'aws_config', 'aws_cloudtrail'])])
def test_aws_discovery_error_with_expired_session_ui(ui, expired_session, integration_type):
    """
    Verify on GUI page that AWS discovery fails with an expired session.

    Given: UI session that sign in to Lacework portal & Invalid IAM role.
    When: Run discovery with expired session.
    Then: Discovery should fail with an error message.

    Args:
        ui: Fixture that open that UI session which sign in to Lacework portal.
        expired_session: Fixture that creates an expired session.
        integration_type: Parametrize data for different integration type.

    Oriole Test Cases:
        1204358 [Expired session] Discovery should fail if Integration token is expired
        1204359 [Expired session] Show error text if Integration token is expired
        1204360 [Expired session] "Back" button is enabled
        1204361 [Expired session] "Integrate" button is disabled
    """
    # Each test will take at least 100 sec, randomly choose one integration type to save time
    integration_data = {
        "integration_method": integration_ui_mapping[integration_type],
        "access_key_id": expired_session["data"]["access_key_id"],
        "secret_access_key": expired_session["data"]["secret_access_key"],
        "session_token": expired_session["data"]["session_token"],
        "default_region": expired_session["data"]["region"],
    }
    ui.settings_onboarding.aws_integration_with_expired_iam_session(integration_data)


@pytest.mark.ui
@pytest.mark.parametrize('integration_type', ['aws_agentless,aws_config,aws_cloudtrail'])
@pytest.mark.parametrize('missing_permission', [random_missing_permission()], indirect=True)
def test_aws_discovery_error_with_missing_permission_ui(ui, active_session, missing_permission, integration_type):
    """
    Verify on GUI that AWS discovery fails with an error message when a required permission is missing.

    Given: UI session that sign in to Lacework portal & Valid IAM role but missing one required permission.
    When: Run discovery with AWS role which missing one required permission.
    Then: Discovery should fail with an error message mentioning the missing permission.

    Args:
        ui: Fixture that open that UI session which sign in to Lacework portal.
        active_session: Fixture that creates a valid session for an IAM role.
        missing_permission: Fixture that creates a missing required permission.

    Oriole Test Cases:
        1204362 [Missing permission] Discovery should fail if missing required permissions
        1204363 [Missing permission] Show discovery error text if missing required permissions
        1204364 [Missing permission] Show list of missing permissions
        1204365 [Missing permission] "Back" button is enabled
        1204366 [Missing permission] "Integrate" button is disabled
    """
    info(f"Testing discovery with missing permission: {missing_permission}")
    integration_data = {
        "integration_method": "",
        "access_key_id": active_session["data"]["access_key_id"],
        "secret_access_key": active_session["data"]["secret_access_key"],
        "session_token": active_session["data"]["session_token"],
        "default_region": active_session["data"]["region"],
    }
    ui.settings_onboarding.aws_integration_with_missing_permission(integration_data, missing_permission)


# test updated permission from dev team
# @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/GROW-2995')
# @pytest.mark.ui
# @pytest.mark.parametrize('integration_type', ['aws_agentless,aws_config,aws_cloudtrail'])
# @pytest.mark.parametrize('missing_permission', [random.choice(xfail_permissions)], indirect=True)
# def test_aws_discovery_error_with_missing_permission_ui_xfail(ui, active_session, missing_permission, integration_type):
    """
    Verify on GUI that AWS discovery fails with an error message when a required permission is missing.
    This test is expected to failed due to Jira ticket: https://lacework.atlassian.net/browse/GROW-2995

    Given: UI session that sign in to Lacework portal & Valid IAM role but missing one required permission.
    When: Run discovery with AWS role which missing one required permission.
    Then: Discovery should fail with an error message mentioning the missing permission.

    Args:
        ui: Fixture that open that UI session which sign in to Lacework portal.
        active_session: Fixture that creates a valid session for an IAM role.
        missing_permission: Fixture that creates a missing required permission.
    """
    # test_aws_discovery_error_with_missing_permission_ui(ui, active_session, missing_permission, integration_type)
