import pytest
import logging
from fortiqa.libs.helper.general_helper import select_random_from_list
from fortiqa.libs.aws.data_class.iam_data_classes import IAMGroup, IAMPolicy
from fortiqa.libs.aws.iam_group import IAMGroupHelper
from fortiqa.libs.aws.iam_policy import IAMPolicyHelper


logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_aws_iam_groups(aws_account) -> list[IAMGroup]:
    """Retrieves all IAM Groups for the AWS account.

    This fixture uses AWS credentials provided by the 'aws_account' fixture to create an instance
    of 'IAMGroupHelper', which fetches all IAM Groups in the account.

    Args:
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.

    Returns:
        list[IAMGroup]: A list of 'IAMGroup' objects representing all IAM Groups found in the account.
    """
    logger.info("Finding all IAM Groups in the AWS account")
    iam_group_helper = IAMGroupHelper(
        region='us-east-2', aws_credentials=aws_account.credentials)
    all_groups = iam_group_helper.get_all_iam_group_objects()
    if all_groups:
        logger.info(f"All IAM Groups for the AWS account:\n{all_groups}")
    else:
        logger.info("There are no IAM Groups for the AWS account.")
    return all_groups


@pytest.fixture(scope='session')
def random_iam_group(all_aws_iam_groups) -> IAMGroup | None:
    """Fixture to select a random IAM Group from the provided list of IAMGroup objects.

    Args:
        all_aws_iam_groups: A list of 'IAMGroup' objects.

    Returns:
        IAMGroup | None: A randomly selected 'IAMGroup' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_iam_groups, "IAM Groups")


@pytest.fixture(scope='session')
def all_aws_iam_policies(aws_account, ingestion_tag: dict[str, str] | None) -> list[IAMPolicy]:
    """Retrieves all IAM Policies for the AWS account, optionally filtering by ingestion tags.

    This fixture uses AWS credentials provided by the 'aws_account' fixture to create an instance
    of 'IAMPolicyHelper', which fetches all IAM Policies in the account. If 'ingestion_tag' is provided,
    only policies with the specified tags are included.

    Args:
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering policies.

    Returns:
        list[IAMPolicy]: A list of 'IAMPolicy' objects representing all IAM Policies found in the account,
                         optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all IAM Policies in the AWS account"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    iam_policy_helper = IAMPolicyHelper(
        region='us-east-2', aws_credentials=aws_account.credentials)
    all_policies = iam_policy_helper.get_all_iam_policy_objects(ingestion_tag)
    if all_policies:
        logger.info(
            f"All IAM Policies for the AWS account"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_policies}"
        )
    else:
        logger.info(f"There are no IAM Policies for the AWS account{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_policies


@pytest.fixture(scope='session')
def random_iam_policy(all_aws_iam_policies) -> IAMPolicy | None:
    """Fixture to select a random IAM Policy from the provided list of IAMPolicy objects.

    Args:
        all_aws_iam_policies: A list of 'IAMPolicy' objects.

    Returns:
        IAMPolicy | None: A randomly selected 'IAMPolicy' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_iam_policies, "IAM Policies")
