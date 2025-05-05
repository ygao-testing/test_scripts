import logging

from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.aws.s3 import S3Helper

logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


class SSMHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client="ssm", region=region, aws_credentials=aws_credentials)

    def run_command(self, command: str, instance_id: str, s3_bucket_name: str) -> str:
        """
        Function to run command on an instance, and store result inside a S3 bucket using SSM agent
        :param command: Command to run on the instance
        :param instance_id: Instance ID
        :param s3_bucket_name: S3 bucket to store the command output
        :return command_id: ID of the command execution
        """
        response = self.client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            OutputS3BucketName=s3_bucket_name
        )
        return response['Command']['CommandId']

    def get_command_output_from_s3(self, command_id: str, instance_id: str, s3_bucket_name: str):
        """
        Function to download the command execution output from S3 bucket
        :param command_id: Command ID
        :param instance_id: Instance ID
        :param s3_bucket_name: S3 bucket to store the command output
        :return output_text: Text in files inside the folder
        """
        folder_name = f"{command_id}/{instance_id}/awsrunShellScript/0.awsrunShellScript/stdout"
        output_text = S3Helper().get_texts_in_all_log_files_inside_folder(bucket_name=s3_bucket_name, folder_name=folder_name)
        return output_text
