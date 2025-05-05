import logging
from typing import Any
from fortiqa.libs.aws.data_class.iam_data_classes import IAMRole
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class IAMRoleHelper(AWSHelper):
    """Helper class for interacting with AWS IAM roles."""

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='iam', region=region, aws_credentials=aws_credentials)

    def get_all_iam_roles_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw IAM role data for the AWS account, optionally filtered by tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        IAM roles based on tags. If None, retrieves all roles.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing raw details for an IAM role.
        """
        logger.info(f"Retrieving IAM Roles from AWS account {self.account_id}")

        response = self.client.list_roles()
        all_roles = response.get("Roles", [])
        logger.debug(f"IAM roles data retrieved from AWS account {self.account_id}: {all_roles}")
        if not tags:
            return all_roles

        # If tags are provided, filter roles by fetching tags for each role
        filtered_roles = []
        for role in all_roles:
            role_name = role.get("RoleName", "Unknown")
            tag_response = self.client.list_role_tags(RoleName=role_name)
            role_tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}
            if all(role_tags.get(key) == value for key, value in tags.items()):
                filtered_roles.append(role)

        logger.debug(f"Filtered IAM roles with tags {tags}. Found {len(filtered_roles)} matching roles: {filtered_roles}")
        return filtered_roles

    def get_all_iam_role_objects(self, tags: dict[str, str] | None = None) -> list[IAMRole]:
        """Convert raw IAM role data to a list of IAMRole objects, optionally filtered by tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        IAM roles based on tags. If None, retrieves all roles.

        Returns:
            list[IAMRole]: A list of 'IAMRole' objects representing each IAM role in the account.
        """
        raw_roles = self.get_all_iam_roles_raw(tags)
        iam_role_objects = []

        for role in raw_roles:
            logger.debug(f"Converting raw IAM role data to object: {role}")
            role_name = role.get("RoleName", "Unknown")

            # Retrieve and attach tags for each role
            tag_response = self.client.list_role_tags(RoleName=role_name)
            role_tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}

            role_obj = IAMRole(
                account_id=settings.app.aws_account.aws_account_id,
                path=role.get("Path", "/"),
                role_name=role.get("RoleName", ""),
                role_id=role.get("RoleId", ""),
                arn=role.get("Arn", ""),
                create_date=datetime_to_iso8601(role.get("CreateDate", "")),
                assume_role_policy_document=role.get("AssumeRolePolicyDocument", {}),
                description=role.get("Description", ""),
                max_session_duration=role.get("MaxSessionDuration", 3600),
                tags=role_tags
            )
            iam_role_objects.append(role_obj)
        return iam_role_objects
