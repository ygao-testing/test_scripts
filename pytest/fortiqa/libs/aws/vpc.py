import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import VPC, CidrBlockAssociation
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class VpcHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_vpcs_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw VPC data for the specified AWS region, optionally filtering by tags.

        Args:
            tags (dict[str, str] | None): Key-value pairs for tag filtering. If None, fetches all VPCs.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
            individual VPC within the specified region, such as VPC ID, CIDR block, owner ID, etc.
        """
        logger.info(f"Retrieving VPCs from AWS account {self.account_id} in region: {self.region}{f', with tags {tags}' if tags else ''}")
        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_vpcs(Filters=filters) if filters else self.client.describe_vpcs()
        vpcs = response.get("Vpcs", [])
        logger.debug(f"VPC data retrieved: {vpcs}")
        return vpcs

    def get_all_vpc_objects(self, tags: dict[str, str] | None = None) -> list[VPC]:
        """Convert raw VPC data to a list of VPC objects for the specified region, optionally filtering by tags.

        This method takes the raw VPC data obtained from the 'get_all_vpcs_raw' method,
        processes each VPC's attributes, and converts them into a list of 'VPC' data
        class objects.

        Args:
            tags (dict[str, str] | None): Key-value pairs for tag filtering. If None, processes all VPCs.

        Returns:
            list[VPC]: A list of 'VPC' objects representing each VPC in the specified region.
        """
        vpcs = self.get_all_vpcs_raw(tags=tags)
        vpc_objects = []
        for vpc in vpcs:
            cidr_block_associations = [
                CidrBlockAssociation(
                    association_id=assoc.get('AssociationId', ''),
                    cidr_block=assoc.get('CidrBlock', ''),
                    cidr_block_state=assoc.get('CidrBlockState', {})
                ) for assoc in vpc.get('CidrBlockAssociationSet', [])
            ]

            tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}

            # Create VPC object using .get() for optional values
            vpc_obj = VPC(
                account_id=settings.app.aws_account.aws_account_id,
                owner_id=vpc.get('OwnerId', ''),
                instance_tenancy=vpc.get('InstanceTenancy', ''),
                cidr_block_association_set=cidr_block_associations,
                is_default=vpc.get('IsDefault', False),
                vpc_id=vpc.get('VpcId', ''),
                state=vpc.get('State', ''),
                cidr_block=vpc.get('CidrBlock', ''),
                dhcp_options_id=vpc.get('DhcpOptionsId', ''),
                tags=tags
            )
            vpc_objects.append(vpc_obj)

        return vpc_objects
