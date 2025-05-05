import pytest
import logging
from fortiqa.libs.aws.s3 import S3Helper
from fortiqa.libs.aws.data_class.s3_data_classes import S3Bucket
from fortiqa.libs.helper.general_helper import select_random_from_list

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_aws_s3_bucket(aws_account, ingestion_tag) -> list[S3Bucket]:
    """Retrieves all S3 buckets for a specified AWS account, optionally filtering by ingestion tags.

    This fixture uses the AWS credentials provided by the 'aws_account' fixture to create
    an instance of 'S3Helper', which fetches all S3 buckets available in the AWS account.
    If 'ingestion_tag' is provided, only buckets with the specified tags are included.

    Args:
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[S3Bucket]: A list of 'S3Bucket' objects representing all S3 buckets found in the AWS account,
                        optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all S3 buckets in AWS account {aws_account.aws_account_id}{f', with tags  {ingestion_tag}' if ingestion_tag else ''}")

    s3_helper = S3Helper(aws_credentials=aws_account.credentials)

    all_s3_buckets = s3_helper.get_all_s3_buckets(ingestion_tag)
    if all_s3_buckets:
        logger.info(f"All S3 Buckets{f', with tags {ingestion_tag}' if ingestion_tag else ''}: \n{all_s3_buckets}")
    else:
        logger.info(
            f"No S3 Buckets found in AWS account {aws_account.aws_account_id}{f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_s3_buckets


@pytest.fixture(scope='session')
def random_s3_bucket(all_aws_s3_bucket, aws_account) -> S3Bucket | None:
    """Fixture to select a random S3 bucket from the provided list of S3 bucket objects.

    Args:
        all_aws_s3_bucket: A list of 'S3Bucket' objects.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.

    Returns:
        S3Bucket | None: A randomly selected 'S3Bucket' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_s3_bucket, f"S3 buckets in account {aws_account.aws_account_id}")
