import logging
from typing import Any
from fortiqa.libs.aws.data_class.iam_data_classes import IAMPolicy
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class IAMPolicyHelper(AWSHelper):
    """Helper class for interacting with AWS IAM policies."""

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='iam', region=region, aws_credentials=aws_credentials)

    def get_all_iam_policies_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw IAM policy data for the AWS account, optionally filtered by tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        IAM policies based on tags. If None, retrieves all policies.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing raw details for an IAM policy.
        """
        logger.info(f"Retrieving IAM Policies from AWS account {self.account_id}")

        response = self.client.list_policies(Scope='Local')
        all_policies = response.get("Policies", [])
        logger.debug(f"IAM policies data retrieved from AWS account {self.account_id}: {all_policies}")
        if not tags:
            return all_policies

        # If tags are provided, filter policies by fetching tags for each policy
        filtered_policies = []
        for policy in all_policies:
            policy_arn = policy.get("Arn", "Unknown")
            tag_response = self.client.list_policy_tags(PolicyArn=policy_arn)
            policy_tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}
            if all(policy_tags.get(key) == value for key, value in tags.items()):
                filtered_policies.append(policy)

        logger.debug(f"Filtered IAM policies with tags {tags}. Found {len(filtered_policies)} matching policies: {filtered_policies}")
        return filtered_policies

    def get_all_iam_policy_objects(self, tags: dict[str, str] | None = None) -> list[IAMPolicy]:
        """Convert raw IAM policy data to a list of IAMPolicy objects, optionally filtered by tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        IAM policies based on tags. If None, retrieves all policies.

        Returns:
            list[IAMPolicy]: A list of 'IAMPolicy' objects representing each IAM policy in the account.
        """
        raw_policies = self.get_all_iam_policies_raw(tags)
        iam_policy_objects = []

        for policy in raw_policies:
            logger.debug(f"Converting raw IAM policy data to object: {policy}")
            policy_arn = policy.get("Arn", "Unknown")

            # Retrieve and attach tags for each policy
            tag_response = self.client.list_policy_tags(PolicyArn=policy_arn)
            policy_tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}

            policy_obj = IAMPolicy(
                account_id=settings.app.aws_account.aws_account_id,
                policy_name=policy.get("PolicyName", ""),
                policy_id=policy.get("PolicyId", ""),
                arn=policy_arn,
                path=policy.get("Path", "/"),
                default_version_id=policy.get("DefaultVersionId", ""),
                attachment_count=policy.get("AttachmentCount", 0),
                permissions_boundary_usage_count=policy.get("PermissionsBoundaryUsageCount", 0),
                is_attachable=policy.get("IsAttachable", False),
                create_date=datetime_to_iso8601(policy.get("CreateDate", "")),
                update_date=datetime_to_iso8601(policy.get("UpdateDate", "")),
                tags=policy_tags
            )
            iam_policy_objects.append(policy_obj)
        return iam_policy_objects
