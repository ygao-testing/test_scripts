import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import InternetGateway, Attachment
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class InternetGatewayHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_internet_gateways_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve internet gateway data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS EC2 'describe_internet_gateways' API to gather information about all
        internet gateways within the specified region. If tags are provided, only internet gateways
        with the specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        internet gateways based on tags. If None, retrieves all internet gateways.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
            individual internet gateway within the specified region.
        """
        logger.info(
            f"Retrieving Internet Gateways from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )
        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_internet_gateways(Filters=filters) if filters else self.client.describe_internet_gateways()
        internet_gateways = response.get("InternetGateways", [])
        logger.debug(
            f"Internet Gateway data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {internet_gateways}"
        )
        return internet_gateways

    def get_all_internet_gateway_objects(self, tags: dict[str, str] | None = None) -> list[InternetGateway]:
        """Convert raw internet gateway data to a list of InternetGateway objects for the specified region,
        optionally filtered by tags.

        This method takes the raw internet gateway data obtained from the 'get_all_internet_gateways_raw' method,
        processes each internet gateway's attributes, and converts them into a list of `InternetGateway` data
        class objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        internet gateways based on tags. If None, retrieves all internet gateways.

        Returns:
            list[InternetGateway]: A list of 'InternetGateway' objects representing each internet gateway in the specified
            region.
        """
        internet_gateways = self.get_all_internet_gateways_raw(tags)
        internet_gateway_objects = []

        for igw in internet_gateways:
            attachments = [
                Attachment(
                    state=attachment.get('State', ''),
                    vpc_id=attachment.get('VpcId', '')
                ) for attachment in igw.get('Attachments', [])
            ]

            tags = {tag['Key']: tag['Value'] for tag in igw.get('Tags', [])}
            # Create InternetGateway object
            igw_obj = InternetGateway(
                account_id=settings.app.aws_account.aws_account_id,
                internet_gateway_id=igw.get('InternetGatewayId', ''),
                owner_id=igw.get('OwnerId', ''),
                attachments=attachments,
                tags=tags
            )
            internet_gateway_objects.append(igw_obj)

        return internet_gateway_objects
