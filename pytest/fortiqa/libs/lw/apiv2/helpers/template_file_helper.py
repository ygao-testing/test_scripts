from fortiqa.libs.lw.apiv2.api_client.cloud_accounts.template_file import TemplateFile


class TemplateFileHelper:
    """
    Helper class for downloading AWS CloudFormation templates from Lacework.

    This class provides methods to download various AWS-related CloudFormation templates
    from the Lacework platform using the API client V2.
    """
    def __init__(self, user_api):
        self.user_api = user_api

    def get_aws_config_template(self):
        """
        Download the AWS Config CloudFormation template from Lacework.

        return: A Response object containing the CloudFormation template.
        """
        return TemplateFile(self.user_api).download_template_file('AwsConfig')

    def get_aws_cloudtrail_template(self):
        """
        Download the AWS CloudTrail CloudFormation template from Lacework.

        return: A Response object containing the CloudFormation template.

        """
        return TemplateFile(self.user_api).download_template_file('AwsCloudTrail')

    def get_aws_eks_audit_template(self):
        """
        Download the AWS EKS Audit CloudFormation template from Lacework.

        return: A Response object containing the CloudFormation template.
        """
        return TemplateFile(self.user_api).download_template_file('AwsEksAudit')

    def get_aws_eks_audit_sub_filter_template(self):
        """
        Download the AWS EKS Audit Subscription Filter CloudFormation template from Lacework.

        return: A Response object containing the CloudFormation template.
        """
        return TemplateFile(self.user_api).download_template_file('AwsEksAuditSubscriptionFilter')
