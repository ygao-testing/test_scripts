# Note: Aws does not support Tags for iam-group
import logging
from typing import Any
from fortiqa.libs.aws.data_class.iam_data_classes import IAMGroup
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class IAMGroupHelper(AWSHelper):
    """Helper class for interacting with AWS IAM groups."""

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='iam', region=region, aws_credentials=aws_credentials)

    def get_all_iam_groups_raw(self) -> list[dict[str, Any]]:
        """Retrieve raw IAM group data for the AWS account.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing raw details for an IAM group.
        """
        logger.info(f"Retrieving IAM Groups from AWS account {self.account_id}")

        response = self.client.list_groups()
        all_groups = response.get("Groups", [])
        logger.debug(f"IAM groups data retrieved from AWS account {self.account_id}: {all_groups}")
        return all_groups

    def get_all_iam_group_objects(self) -> list[IAMGroup]:
        """Convert raw IAM group data to a list of IAMGroup objects.

        Returns:
            list[IAMGroup]: A list of 'IAMGroup' objects representing each IAM group in the account.
        """
        raw_groups = self.get_all_iam_groups_raw()
        iam_group_objects = []

        for group in raw_groups:
            logger.debug(f"Converting raw IAM group data to object: {group}")
            group_obj = IAMGroup(
                account_id=settings.app.aws_account.aws_account_id,
                path=group.get("Path", "/"),
                group_name=group.get("GroupName", ""),
                group_id=group.get("GroupId", ""),
                arn=group.get("Arn", ""),
                create_date=datetime_to_iso8601(group.get("CreateDate", ""))
            )
            iam_group_objects.append(group_obj)
        return iam_group_objects
