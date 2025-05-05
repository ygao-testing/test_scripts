import boto3
import logging

log = logging.getLogger(__name__)


class AWSHelper:
    def __init__(self, boto3_client: str,
                 region='us-east-2',
                 aws_credentials: dict = {}):
        """
        Init boto3 client
        :param boto3_client: Name of the client
        :param region: Region of the boto3 client
        :param aws_credentials:
            If None, use default environment variables
            Else, use passed aws_access_key_id and aws_secret_access_key
        """
        if aws_credentials:
            self.client = boto3.client(boto3_client, region_name=region,
                                       aws_access_key_id=aws_credentials['aws_access_key_id'],
                                       aws_secret_access_key=aws_credentials['aws_secret_access_key'])
            sts = boto3.client("sts", region_name=region,
                               aws_access_key_id=aws_credentials['aws_access_key_id'],
                               aws_secret_access_key=aws_credentials['aws_secret_access_key'])
            self.account_id = sts.get_caller_identity()["Account"]
            logging.info(f"boto3 client for AWS account: ####{self.account_id}#### created")

        else:
            self.client = boto3.client(boto3_client, region_name=region)
            sts = boto3.client("sts", region_name=region)
            self.account_id = sts.get_caller_identity()["Account"]
            logging.info(f"boto3 client for AWS account: ####{self.account_id}#### created")
        self.region = region
        self.aws_credentials = aws_credentials
