from datetime import datetime

from fortiqa.libs.aws.awshelper import AWSHelper


class STSHelper(AWSHelper):

    def __init__(self, region='us-west-2', aws_credentials: dict = {}):
        super().__init__(
            boto3_client='sts',
            region=region,
            aws_credentials=aws_credentials,
        )

    def assume_role(self, role_arn: str = '', duration: int = 900):
        """
        Assume a role for the duration specified.

        Args:
            role_arn (str): The ARN of the role to assume.
            duration (int): The duration in seconds to assume the role.

        Returns:
            dict: The response from the client, which includes the temporary
                credentials and the assumed role ID.
        """
        session_name = f'session{datetime.now().strftime("%H%M%S")}'
        return self.client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration,
        )
