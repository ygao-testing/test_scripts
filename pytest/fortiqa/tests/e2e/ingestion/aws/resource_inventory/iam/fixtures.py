import pytest
import logging
from fortiqa.libs.helper.general_helper import select_random_from_list
from fortiqa.libs.aws.data_class.iam_data_classes import IAMUser, IAMRole
from fortiqa.libs.aws.iam_role import IAMRoleHelper
from fortiqa.libs.aws.iam_user import IAMUserHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_aws_iam_users(aws_account, ingestion_tag) -> list[IAMUser]:
    """Retrieves all IAM Users for the AWS account, optionally filtering by ingestion tags.

    This fixture uses AWS credentials provided by the 'aws_account' fixture to create an instance
    of 'IAMUserHelper', which fetches all IAM Users in the account. If 'ingestion_tag' is provided,
    only users with the specified tags are included.

    Args:
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering users.

    Returns:
        list[IAMUser]: A list of 'IAMUser' objects representing all IAM Users found in the account,
                       optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all IAM Users in the AWS account"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    iam_user_helper = IAMUserHelper(
        region='us-east-2', aws_credentials=aws_account.credentials)
    all_users = iam_user_helper.get_all_iam_user_objects(ingestion_tag)
    if all_users:
        logger.info(
            f"All IAM Users for the AWS account"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{all_users}"
        )
    else:
        logger.info(
            f"There are no IAM Users for the AWS account{f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_users


@pytest.fixture(scope='session')
def random_iam_user(all_aws_iam_users) -> IAMUser | None:
    """Fixture to select a random IAM User from the provided list of IAMUser objects.

    Args:
        all_aws_iam_users_region: A list of 'IAMUser' objects.

    Returns:
        IAMUser | None: A randomly selected 'IAMUser' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_iam_users, "IAM Users")


@pytest.fixture(scope='session')
def all_aws_iam_roles(aws_account, ingestion_tag: dict[str, str] | None) -> list[IAMRole]:
    """Retrieves all IAM Roles for the AWS account, optionally filtering by ingestion tags.

    This fixture uses AWS credentials provided by the 'aws_account' fixture to create an instance
    of 'IAMRoleHelper', which fetches all IAM Roles in the account. If 'ingestion_tag' is provided,
    only roles with the specified tags are included.

    Args:
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering roles.

    Returns:
        list[IAMRole]: A list of 'IAMRole' objects representing all IAM Roles found in the account,
                       optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all IAM Roles in the AWS account"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    iam_role_helper = IAMRoleHelper(
        region='us-east-2', aws_credentials=aws_account.credentials)
    all_roles = iam_role_helper.get_all_iam_role_objects(ingestion_tag)
    if all_roles:
        logger.info(
            f"All IAM Roles for the AWS account"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{all_roles}"
        )
    else:
        logger.info(
            f"There are no IAM Roles for the AWS account{f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_roles


@pytest.fixture(scope='session')
def random_iam_role(all_aws_iam_roles) -> IAMRole | None:
    """Fixture to select a random IAM Role from the provided list of IAMRole objects.

    Args:
        all_aws_iam_roles: A list of 'IAMRole' objects.

    Returns:
        IAMRole | None: A randomly selected 'IAMRole' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_iam_roles, "IAM Roles")
