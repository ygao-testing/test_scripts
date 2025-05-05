import logging

from fortiqa.libs.aws.iam import IAMHelper

logger = logging.getLogger(__name__)

RISKS_MAPPING = {
    "IAMFullAccess": "ALLOWS_IAM_WRITE",
    "AmazonS3FullAccess": "ALLOWS_STORAGE_WRITE",
    "AmazonS3ReadOnlyAccess": "ALLOWS_STORAGE_READ",
    "SecretsManagerReadWrite": "ALLOWS_SECRETS_READ",
}


def test_iam_users_existence(api_v2_client, categorize_identities, tf_iam_users):
    """
    Verify that created IAM users can be found inside Lacework

    Given: A list of IAM users created by Terraform, and a dictionary contains all indentities inside Lacework
    When: Check if the IAM user can be found inside that dictionary
    Then: The IAM user's Arn should exist in Lacework's identity

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        categorize_identities: A categorized dictionary containing all identities in Lacework based on platform
        tf_iam_users: Created IAM user's info
    """
    all_users = categorize_identities['aws']['iam_user']
    tf_user_arn = tf_iam_users['arn']
    assert tf_user_arn in all_users, f"Cannot find {tf_iam_users} inside Lacework"


def test_iam_users_risk(api_v2_client, categorize_identities, tf_iam_users):
    """
    Verify that created IAM users with specific risk could match the Identity risk in Lacework

    Given: A list of IAM users created by Terraform, and a dictionary contains all indentities inside Lacework
    When: Using Boto3 IAM package to get the policies of IAM user, and check if the IAM user's risk can be found inside that dictionary
    Then: The IAM user's risk should match Lacework
    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        categorize_identities: A categorized dictionary containing all identities in Lacework based on platform
        tf_iam_users: Created IAM user's info
    """
    all_users = categorize_identities['aws']['iam_user']
    all_users_in_aws = IAMHelper().list_all_users_and_policies()
    tf_user_arn = tf_iam_users['arn']
    policy_associated = all_users_in_aws[tf_user_arn]['attached_policies'].keys()
    risks_in_lacework = all_users[tf_user_arn]['RISKS']
    assert 'PASSWORD_LOGIN_NO_MFA' in risks_in_lacework, f"Expected {tf_iam_users} has risk PASSWORD_LOGIN_NO_MFA, but not found"
    for policy in policy_associated:
        if policy in RISKS_MAPPING:
            assert RISKS_MAPPING[policy] in risks_in_lacework, f"Expected {tf_iam_users} has risk {RISKS_MAPPING[policy]} for IAM policy {policy}, but not found"


def test_iam_roles_existence(api_v2_client, categorize_identities, tf_iam_roles):
    """
    Verify that created IAM roles can be found inside Lacework

    Given: A list of IAM roles created by Terraform, and a dictionary contains all indentities inside Lacework
    When: Check if the IAM role can be found inside that dictionary
    Then: The IAM role's Arn should exist in Lacework's identity

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        categorize_identities: A categorized dictionary containing all identities in Lacework based on platform
        tf_iam_roles: Created IAM role's info
    """
    all_roles = categorize_identities['aws']['iam_role']
    tf_role_arn = tf_iam_roles['arn']
    assert tf_role_arn in all_roles, f"Cannot find {tf_iam_roles} inside Lacework"


def test_iam_roles_risk(api_v2_client, categorize_identities, tf_iam_roles):
    """
    Verify that created IAM roles with specific risk could match the Identity risk in Lacework

    Given: A list of IAM roles created by Terraform, and a dictionary contains all indentities inside Lacework
    When: Using Boto3 IAM package to get the policies of IAM role, and check if the IAM role's risk can be found inside that dictionary
    Then: The IAM role's risk should match Lacework
    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        categorize_identities: A categorized dictionary containing all identities in Lacework based on platform
        tf_iam_roles: Created IAM role's info
    """
    all_roles = categorize_identities['aws']['iam_role']
    all_roles_in_aws = IAMHelper().list_all_roles_and_policies()
    tf_role_arn = tf_iam_roles['arn']
    policy_associated = all_roles_in_aws[tf_role_arn]['attached_policies'].keys()
    risks_in_lacework = all_roles[tf_role_arn]['RISKS']
    for policy in policy_associated:
        if policy in RISKS_MAPPING:
            assert RISKS_MAPPING[policy] in risks_in_lacework, f"Expected {tf_iam_roles} has risk {RISKS_MAPPING[policy]} for IAM policy {policy}, but not found"
