import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import NatGateway, NatGatewayAddress
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class NatGatewayHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_nat_gateways_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve NAT Gateway data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS EC2 'describe_nat_gateways' API to gather information about all
        NAT Gateways within the specified region. If tags are provided, only NAT Gateways with the
        specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        NAT Gateways based on tags. If None, retrieves all NAT Gateways.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
            individual NAT Gateway within the specified region.
        """
        logger.info(
            f"Retrieving NAT Gateways from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )

        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_nat_gateways(Filters=filters) if filters else self.client.describe_nat_gateways()
        nat_gateways = response.get("NatGateways", [])
        logger.debug(
            f"NAT Gateway data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {nat_gateways}"
            )
        return nat_gateways

    def get_all_nat_gateway_objects(self, tags: dict[str, str] | None = None) -> list[NatGateway]:
        """Convert raw NAT Gateway data to a list of NatGateway objects for the specified region,
        optionally filtered by tags.

        This method takes the raw NAT Gateway data obtained from the 'get_all_nat_gateways_raw' method,
        processes each NAT Gateway's attributes, and converts them into a list of 'NatGateway' data
        class objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        NAT Gateways based on tags. If None, retrieves all NAT Gateways.

        Returns:
            list[NatGateway]: A list of NatGateway' objects representing each NAT Gateway in the specified
            region.
        """
        nat_gateways = self.get_all_nat_gateways_raw(tags)
        nat_gateway_objects = []

        for nat_gateway in nat_gateways:
            # Convert NAT Gateway addresses
            nat_gateway_addresses = [
                NatGatewayAddress(
                    allocation_id=address.get('AllocationId', ''),
                    network_interface_id=address.get('NetworkInterfaceId', ''),
                    private_ip=address.get('PrivateIp', ''),
                    public_ip=address.get('PublicIp', ''),
                    association_id=address.get('AssociationId', ''),
                    is_primary=address.get('IsPrimary', False),
                    status=address.get('Status', '')
                ) for address in nat_gateway.get('NatGatewayAddresses', [])
            ]

            # Convert tags to dictionary
            tags = {tag['Key']: tag['Value'] for tag in nat_gateway.get('Tags', [])}

            # Create NatGateway object using .get() for optional values
            nat_gateway_obj = NatGateway(
                nat_gateway_id=nat_gateway.get('NatGatewayId', ''),
                account_id=settings.app.aws_account.aws_account_id,
                create_time=nat_gateway.get('CreateTime', ''),
                state=nat_gateway.get('State', ''),
                subnet_id=nat_gateway.get('SubnetId', ''),
                vpc_id=nat_gateway.get('VpcId', ''),
                connectivity_type=nat_gateway.get('ConnectivityType', ''),
                nat_gateway_addresses=nat_gateway_addresses,
                tags=tags
            )
            nat_gateway_objects.append(nat_gateway_obj)

        return nat_gateway_objects
