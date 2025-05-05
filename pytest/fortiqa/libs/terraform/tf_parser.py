import logging

import tftest

logger = logging.getLogger(__name__)


class TFParser:
    """Parses Terraform state files to extract cloud accounts, alert rules, IAM resources, etc."""
    def __init__(self, working_dirs: list | str = []):
        """
        Initialize the TFParser with working directories containing Terraform state files.

        Args:
            working_dirs (list | str): One or more directories containing Terraform state files.
        """
        if type(working_dirs) is str:
            working_dirs = [working_dirs]
        self.tf_states = [tftest.TerraformTest(tfdir=wd).state_pull() for wd in working_dirs]
        self.tf_resources = []
        for state in self.tf_states:
            self.tf_resources.extend(state['resources'])

    def get_resources_by_types(self, resource_types: list) -> list:
        """
        Retrieve Terraform resources that match the specified resource types.

        Args:
            resource_types (list): List of resource types to filter.

        Returns:
            list: A list of resources that match the given types.
        """
        res = []
        for resource in self.tf_resources:
            if resource.get('type') in resource_types:
                res.extend(resource.get('instances', []))
        return res

    def get_lw_cloud_accounts(self) -> list:
        """
        Extract Lacework cloud account integration resources from the Terraform state.

        Returns:
            list: A list of dictionaries containing cloud account details (name, type, intg_guid).
        """
        cloud_accounts = []
        for resource in self.get_resources_by_types([
            'lacework_integration_aws_agentless_scanning',
            'lacework_integration_aws_cfg',
            'lacework_integration_aws_ct',
            'lacework_integration_aws_eks_audit_log',
            'lacework_integration_aws_govcloud_cfg',
            'lacework_integration_aws_govcloud_ct',
            'lacework_integration_aws_org_agentless_scanning'
        ]):
            cloud_accounts.append({
                'name': resource.get('attributes', {}).get('name'),
                'type': resource.get('attributes', {}).get('type_name'),
                'intg_guid': resource.get('attributes', {}).get('intg_guid')})
        return cloud_accounts

    def get_lw_alert_rules(self) -> list:
        """
        Extract Lacework alert rules from the Terraform state.

        Returns:
            list: A list of dictionaries containing alert rule details (name, alert_channels).
        """
        alert_rules = []
        for resource in self.get_resources_by_types(["lacework_alert_rule"]):
            alert_rules.append(resource.get('attributes', {}))
        return alert_rules

    def get_lw_alert_profiles(self) -> list:
        """
        Extract Lacework alert profiles from the Terraform state.
        To be matched with the alert profiles returned by the Lacework API.
        Keyword naming follows the Lacework API naming convention.

        Returns:
            list: A list of dictionaries containing alert profile details
                  (name, eventName, description, subject).
        """
        alert_profiles = []

        for resource in self.get_resources_by_types(["lacework_alert_profile"]):
            alert_profiles.append(resource.get('attributes', {}))
        return alert_profiles

    def get_lw_email_alert_channels(self) -> list:
        """
        Extract Lacework email alert channels from the Terraform state.

        Returns:
            list: A list of dictionaries containing email alert channel details.
        """
        email_alert_channels = []
        for resource in self.get_resources_by_types(["lacework_alert_channel_email"]):
            email_alert_channels.append(resource.get('attributes', {}))
        return email_alert_channels

    def get_lw_report_rules(self) -> list:
        """
        Extract Lacework report rules from the Terraform state.

        Returns:
            list: A list of dictionaries containing report rule details (name, description, resource_group_guid).
        """
        report_rules = []
        for resource in self.get_resources_by_types(["lacework_report_rule"]):
            report_rules.append(resource.get('attributes', {}))
        return report_rules

    def get_s3_buckets(self) -> list:
        """
        Extract AWS S3 bucket resources from the Terraform state.

        Returns:
            list: A list of dictionaries containing S3 bucket details (name, arn).
        """
        s3_buckets = []
        for resource in self.get_resources_by_types(['aws_s3_bucket']):
            s3_buckets.append({
                'name': resource.get('attributes', {}).get('bucket'),
                'arn': resource.get('attributes', {}).get('arn'),
            })
        return s3_buckets

    def get_iam_users(self) -> list:
        """
        Extract AWS IAM user resources from the Terraform state.

        Returns:
            list: A list of dictionaries containing IAM user details (name, arn).
        """
        iam_users = []
        for resource in self.get_resources_by_types(['aws_iam_user']):
            iam_users.append({
                'name': resource.get('attributes', {}).get('name'),
                'arn': resource.get('attributes', {}).get('arn'),
            })
        return iam_users

    def get_iam_roles(self) -> list:
        """
        Extract AWS IAM role resources from the Terraform state.

        Returns:
            list: A list of dictionaries containing IAM role details (name, arn).
        """
        iam_roles = []
        for resource in self.get_resources_by_types(['aws_iam_role']):
            iam_roles.append({
                'name': resource.get('attributes', {}).get('name'),
                'arn': resource.get('attributes', {}).get('arn'),
            })
        return iam_roles

    def get_lw_resource_groups(self) -> list:
        """
        Extract Lacework resource group resources from the Terraform state.

        Returns:
            list: list of dictionaries containing resource group details (name, alert_channels).
        """
        resource_groups = []
        for resource in self.get_resources_by_types(["lacework_resource_group"]):
            resource_groups.append(resource.get('attributes', {}))
        return resource_groups

    def get_lw_policies(self) -> list:
        """
        Extract Lacework policies from the Terraform state.

        Returns:
            list of dictionaries containing policy details.
            Will be parsed into dataclass in the test.
        """
        policies = []
        for resource in self.get_resources_by_types(["lacework_policy"]):
            policies.append(resource.get('attributes', {}))
        return policies
