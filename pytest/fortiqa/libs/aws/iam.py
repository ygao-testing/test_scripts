from collections import defaultdict
import logging
import json
from fortiqa.libs.aws.awshelper import AWSHelper


logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
log = logging.getLogger(__name__)


class IAMHelper(AWSHelper):

    def __init__(self, region='us-west-2', aws_credentials: dict = {}):
        super().__init__(boto3_client="iam", region=region, aws_credentials=aws_credentials)

    def list_users(self) -> dict:
        """
        Helper function to list all IAM users inside AWS account
        :return: A dictionary contains all IAM users' info
        """
        log.info("list_users()")
        response = self.client.list_users()
        return response

    def list_roles(self) -> dict:
        """
        Helper function to list all IAM roles inside AWS account
        :return: A dictionary contains all IAM roles' info
        """
        log.info("list_roles()")
        response = self.client.list_roles()
        return response

    def list_attached_policies_of_iam_user(self, user_name: str) -> dict:
        """
        Helper function to list all managed policies that are attached to the specific IAM user
        :param user_name: IAM username
        :return: A dictionary contains this IAM user's attached policies
        """
        log.info(f"list_attached_policies_of_iam_user() for {user_name}")
        response = self.client.list_attached_user_policies(UserName=user_name)
        return response

    def list_custom_inline_policies_of_iam_user(self, user_name: str) -> dict:
        """
        Helper function to list all custom inline polices that are attached to the specific IAM user
        :param user_name: IAM username
        :return: A dictionary contains this IAM user's custom inline polices
        """
        log.info(f"list_custom_inline_policies_of_iam_user() for {user_name}")
        response = self.client.list_user_policies(UserName=user_name)
        return response

    def list_attached_policies_of_iam_role(self, role_name: str) -> dict:
        """
        Helper function to list all managed policies that are attached to the specific IAM role
        :param role_name: IAM role name
        :return: A dictionary contains this IAM role's attached policies
        """
        log.info(f"list_attached_policies_of_iam_role() for {role_name}")
        response = self.client.list_attached_role_policies(RoleName=role_name)
        return response

    def list_custom_inline_policies_of_iam_role(self, role_name: str) -> dict:
        """
        Helper function to list all custom inline polices that are attached to the specific IAM role
        :param user_name: IAM role name
        :return: A dictionary contains this IAM role's custom inline polices
        """
        log.info(f"list_custom_inline_policies_of_iam_role() for {role_name}")
        response = self.client.list_role_policies(RoleName=role_name)
        return response

    def get_policy_version(self, policy_arn: str, policy_version_id: str) -> dict:
        """
        Helper function to retrieve information about the specified version of the specified managed policy, including the policy document.
        :param policy_arn: ARN of the managed policy that you want information about.
        :param policy_version_id: Identifies the policy version to retrieve.
        :return: A dictionary contains detail info about this policy
        """
        log.info(f"get_policy_version() for {policy_arn=}, {policy_version_id=}")
        response = self.client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)
        return response

    def list_all_users_and_policies(self) -> dict:
        """
        Helper function to list all IAM users and their attached policies
        :return: A dictionary contains detail info about all IAM users and policies attached to them
        """
        log.info("list_all_users_and_policies()")
        users = self.list_users()
        detail_info: defaultdict[str, defaultdict[str, dict]] = defaultdict(lambda: defaultdict(dict))

        for user in users['Users']:
            name = user['UserName']
            policies = self.list_attached_policies_of_iam_user(name)['AttachedPolicies']
            arn = user['Arn']
            for policy in policies:
                policy_detail = self.get_policy_version(policy_arn=policy['PolicyArn'], policy_version_id='v1')
                detail_info[arn]['attached_policies'][policy['PolicyName']] = policy_detail['PolicyVersion']['Document']['Statement']
            # Check inline policies
            inline_policies_names = self.list_custom_inline_policies_of_iam_user(name)['PolicyNames']
            for inline_policy in inline_policies_names:
                policy_document = self.client.get_user_policy(UserName=name, PolicyName=inline_policy)
                detail_info[arn]['inline_policies'][inline_policy] = policy_document['PolicyDocument']['Statement']
            detail_info[arn]['user_name'] = name
            detail_info[arn]['arn'] = arn
        return detail_info

    def list_all_roles_and_policies(self) -> dict:
        """
        Helper function to list all IAM roles and their attached policies
        :return: A dictionary contains detail info about all IAM roles and policies attached to them
        """
        log.info("list_all_roles_and_policies()")
        roles = self.list_roles()
        detail_info: defaultdict[str, defaultdict[str, dict]] = defaultdict(lambda: defaultdict(dict))
        for role in roles['Roles']:
            name = role['RoleName']
            policies = self.list_attached_policies_of_iam_role(name)['AttachedPolicies']
            arn = role['Arn']
            for policy in policies:
                policy_detail = self.get_policy_version(policy_arn=policy['PolicyArn'], policy_version_id='v1')
                detail_info[arn]['attached_policies'][policy['PolicyName']] = policy_detail['PolicyVersion']['Document']['Statement']
            # Check inline policies
            inline_policies_names = self.list_custom_inline_policies_of_iam_role(name)['PolicyNames']
            for inline_policy in inline_policies_names:
                policy_document = self.client.get_role_policy(RoleName=name, PolicyName=inline_policy)
                detail_info[arn]['inline_policies'][inline_policy] = policy_document['PolicyDocument']['Statement']
            detail_info[arn]['role_name'] = name
            detail_info[arn]['arn'] = arn
        return detail_info

    def create_policy(self, policy_template: dict, policy_name: str) -> dict:
        """
        Helper function to create IAM policy using template
        :param policy_template: Dictionary represents the policy document
        :param policy_name: Name of the policy
        :return: A dictionary represents policy info
        """
        log.info(f"Create IAM policy {policy_name}")
        response = self.client.create_policy(
            Path="/service-policy/",
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_template)
        )
        return response

    def create_role(self, role_name: str, assume_role_policy_document: str) -> dict:
        """
        Helper function to create IAM role using template
        :param role_name: Name of the role
        :param assume_role_policy_document: Dictionary represents the policy document
        :return: A dictionary represents role info
        """
        log.info(f"Create IAM role {role_name}")
        response = self.client.create_role(
            Path="/service-role/",
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
        )
        return response

    def attach_policy_to_role(self, role_name: str, policy_arn: str) -> dict:
        """
        Helper function to attach the IAM role to the policy
        :param role_name: Name of the role
        :param policy_arn: Arn of the policy
        :return: boto3 response
        """
        log.info(f"Attach policy with {policy_arn=} to {role_name=}")
        response = self.client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        return response

    def delete_role(self, role_name: str) -> None:
        """
        Function to delete an IAM role
        :param role_name: Name of the role
        """
        log.info(f"Delete IAM role {role_name}")
        self.client.delete_role(
            RoleName=role_name
        )

    def delete_policy(self, policy_arn: str) -> None:
        """
        Function to delete a policy
        :param policy_arn: ARN of the policy
        """
        log.info(f"Delete IAM policy {policy_arn}")
        self.client.delete_policy(
            PolicyArn=policy_arn
        )

    def list_iam_users_have_access_to_specic_s3_bucket(self) -> dict:
        """
        Function to list all IAM users that have access to specific S3 bucket or object

        :return: Dictionary contains IAM users and policies info
        """
        iam_users = self.list_all_users_and_policies()
        result: defaultdict[str, defaultdict[str, defaultdict[str, list]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for iam_user_arn, iam_user_info in iam_users.items():
            name = iam_user_info['user_name']
            if 'inline_policies' in iam_user_info:
                for policy_name, policy_info in iam_user_info['inline_policies'].items():
                    for action_info in policy_info:
                        if any("s3" in action for action in action_info['Action']):
                            result[iam_user_arn]['user_name'] = name
                            result[iam_user_arn]["s3_policies"][policy_name].append(action_info)
        return result

    def list_iam_roles_have_access_to_specic_s3_bucket(self) -> dict:
        """
        Function to list all IAM roles that have access to specific S3 bucket or object

        :return: Dictionary contains IAM roles and policies info
        """
        iam_roles = self.list_all_roles_and_policies()
        result: defaultdict[str, defaultdict[str, defaultdict[str, list]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for iam_role_arn, iam_role_info in iam_roles.items():
            name = iam_role_info['role_name']
            if 'inline_policies' in iam_role_info:
                for policy_name, policy_info in iam_role_info['inline_policies'].items():
                    for action_info in policy_info:
                        if any("s3" in action for action in action_info['Action']):
                            result[iam_role_arn]['role_name'] = name
                            result[iam_role_arn]["s3_policies"][policy_name].append(action_info)
        return result
