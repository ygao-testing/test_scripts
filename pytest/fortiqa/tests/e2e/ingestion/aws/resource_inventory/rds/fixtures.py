import logging
import pytest
from fortiqa.libs.aws.data_class.rds_data_classes import DBInstance
from fortiqa.libs.aws.rds_db_instance import RdsDbInstanceHelper
from fortiqa.libs.helper.general_helper import select_random_from_list

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_aws_rds_db_instances_region(aws_region, aws_account, ingestion_tag) -> list[DBInstance]:
    """Retrieves all RDS DB Instances for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve RDS DB Instances. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'RDSHelper', which fetches all RDS DB Instances
    in the specified region. If 'ingestion_tag' is provided, only instances with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve RDS DB Instances from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        List[DBInstance]: A list of 'DBInstance' objects representing all RDS DB Instances found in the specified region,
                          optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all RDS DB Instances in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    rds_helper = RdsDbInstanceHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_instances = rds_helper.get_all_rds_db_instance_objects(ingestion_tag)
    if all_instances:
        logger.info(
            f"All RDS DB Instances for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{all_instances}"
        )
    else:
        logger.info(
            f"There are no RDS DB Instances for region: {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
        )
    return all_instances


@pytest.fixture(scope='session')
def random_rds_db_instance(all_aws_rds_db_instances_region, aws_region) -> DBInstance | None:
    """Fixture to select a random RDS DB Instance from the provided list of DBInstance objects.

    Args:
        all_aws_rds_instances_region : A list of 'DBInstance' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        DBInstance | None: A randomly selected 'DBInstance' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_rds_db_instances_region, f"RDS DB Instances in region {aws_region}")
