import logging
from typing import Any
from fortiqa.libs.aws.data_class.iam_data_classes import IAMUser
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class IAMUserHelper(AWSHelper):
    """Helper class for interacting with AWS IAM users."""

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='iam', region=region, aws_credentials=aws_credentials)

    def get_all_iam_users_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw IAM user data for the AWS account, optionally filtered by tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        IAM users based on tags. If None, retrieves all users.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing raw details for an IAM user.
        """
        logger.info(f"Retrieving IAM Users from AWS account {self.account_id}")

        response = self.client.list_users()
        all_users = response.get("Users", [])
        logger.debug(f"IAM users data retrieved from AWS account {self.account_id}: {all_users}")
        if not tags:
            return all_users

        # If tags are provided, filter users by fetching tags for each user
        filtered_users = []
        for user in all_users:
            user_name = user.get("UserName", "Unknown")
            tag_response = self.client.list_user_tags(UserName=user_name)
            user_tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}
            if all(user_tags.get(key) == value for key, value in tags.items()):
                filtered_users.append(user)

        logger.debug(f"Filtered IAM users with tags {tags}. Found {len(filtered_users)} matching users: {filtered_users}")
        return filtered_users

    def get_all_iam_user_objects(self, tags: dict[str, str] | None = None) -> list[IAMUser]:
        """Convert raw IAM user data to a list of IAMUser objects, optionally filtered by tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        IAM users based on tags. If None, retrieves all users.

        Returns:
            list[IAMUser]: A list of 'IAMUser' objects representing each IAM user in the account.
        """
        raw_users = self.get_all_iam_users_raw(tags)
        iam_user_objects = []

        for user in raw_users:
            logger.debug(f"Converting raw IAM user data to object: {user}")
            user_name = user.get("UserName", "Unknown")

            # Retrieve and attach tags for each user
            tag_response = self.client.list_user_tags(UserName=user_name)
            user_tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}

            user_obj = IAMUser(
                account_id=settings.app.aws_account.aws_account_id,
                path=user.get("Path", "/"),
                user_name=user.get("UserName", ""),
                user_id=user.get("UserId", ""),
                arn=user.get("Arn", ""),
                create_date=datetime_to_iso8601(user.get("CreateDate", "")),
                password_last_used=datetime_to_iso8601(user.get("PasswordLastUsed")) if user.get("PasswordLastUsed") else None,
                tags=user_tags
            )
            iam_user_objects.append(user_obj)
        return iam_user_objects

    def create_iam_user(self, user_name: str, path: str = "/", tags: dict[str, str] | None = None) -> IAMUser:
        """Create a new IAM user in the AWS account and generate access keys.

        Args:
            user_name (str): The name of the IAM user to create.
            path (str, optional): The path for the IAM user. Defaults to "/".
            tags (dict[str, str] | None, optional): A dictionary of tags to attach to the user.

        Returns:
            IAMUser: An IAMUser object representing the created user, including access keys.

        Raises:
            ClientError: If the user creation fails or if a user with the same name already exists.
        """
        logger.info(f"Creating IAM User {user_name} in AWS account {self.account_id}")

        create_args = {"UserName": user_name, "Path": path, "Tags": [{}]}
        if tags:
            create_args["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]

        response = self.client.create_user(**create_args)
        user_data = response["User"]

        # Generate access keys for the user
        logger.info(f"Generating access keys for IAM User {user_name}")
        key_response = self.client.create_access_key(UserName=user_name)
        access_key_data = key_response["AccessKey"]

        # Convert the response to an IAMUser object
        user_obj = IAMUser(
            account_id=settings.app.aws_account.aws_account_id,
            path=user_data.get("Path", "/"),
            user_name=user_data.get("UserName", ""),
            user_id=user_data.get("UserId", ""),
            arn=user_data.get("Arn", ""),
            create_date=datetime_to_iso8601(user_data.get("CreateDate", "")),
            password_last_used=None,
            tags=tags or {},
            access_key_id=access_key_data["AccessKeyId"],
            secret_access_key=access_key_data["SecretAccessKey"]
        )

        logger.debug(f"Successfully created IAM user with access keys: {user_name}")
        return user_obj

    def delete_iam_user(self, user_name: str) -> bool:
        """Delete an IAM user from the AWS account.

        Args:
            user_name (str): The name of the IAM user to delete.

        Returns:
            bool: True if the user was successfully deleted, False otherwise.

        Raises:
            ClientError: If the user deletion fails or if the user doesn't exist.
        """
        logger.info(f"Deleting IAM User {user_name} from AWS account {self.account_id}")

        try:
            # First, list and remove any attached policies
            attached_policies = self.client.list_attached_user_policies(UserName=user_name)
            for policy in attached_policies.get("AttachedPolicies", []):
                self.client.detach_user_policy(
                    UserName=user_name,
                    PolicyArn=policy["PolicyArn"]
                )

            # Delete any inline policies
            inline_policies = self.client.list_user_policies(UserName=user_name)
            for policy_name in inline_policies.get("PolicyNames", []):
                self.client.delete_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )

            # Delete access keys
            access_keys = self.client.list_access_keys(UserName=user_name)
            for key in access_keys.get("AccessKeyMetadata", []):
                self.client.delete_access_key(
                    UserName=user_name,
                    AccessKeyId=key["AccessKeyId"]
                )

            # Finally delete the user
            self.client.delete_user(UserName=user_name)
            logger.debug(f"Successfully deleted IAM user: {user_name}")
            return True

        except self.client.exceptions.NoSuchEntityException:
            logger.warning(f"IAM user {user_name} not found in account {self.account_id}")
            return False

    def attach_policy_to_user(self, user_name: str, policy_name: str) -> None:
        """Attach an AWS managed policy to an existing IAM user.

        Args:
            user_name (str): The name of the IAM user to attach the policy to.
            policy_name (str): The name of the AWS managed policy to attach (e.g., 'AmazonEC2ContainerRegistryReadOnly').

        Raises:
            ClientError: If the policy attachment fails or if the user/policy doesn't exist.
        """
        logger.info(f"Attaching policy {policy_name} to IAM User {user_name}")

        # Construct the ARN for the AWS managed policy
        policy_arn = f"arn:aws:iam::aws:policy/{policy_name}"

        try:
            self.client.attach_user_policy(
                UserName=user_name,
                PolicyArn=policy_arn
            )
            logger.info(f"Successfully attached policy {policy_name} to user {user_name}")
        except self.client.exceptions.ClientError as e:
            logger.error(f"Failed to attach policy {policy_name} to user {user_name}: {str(e)}")
            raise
