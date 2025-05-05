import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import RouteTable, Route, RouteTableAssociation
from fortiqa.libs.aws.awshelper import AWSHelper

logger = logging.getLogger(__name__)


class RouteTableHelper(AWSHelper):
    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_route_tables_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve Route Table data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS EC2 'describe_route_tables' API to gather information about all
        Route Tables within the specified region. If tags are provided, only Route Tables with the
        specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                          Route Tables based on tags. If None, retrieves all Route Tables.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
                                  individual Route Table within the specified region.
        """
        logger.info(
            f"Retrieving Route Tables from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )
        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_route_tables(Filters=filters) if filters else self.client.describe_route_tables()
        route_tables = response.get("RouteTables", [])
        logger.debug(
            f"Route Table data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {route_tables}"
        )
        return route_tables

    def get_all_route_table_objects(self, tags: dict[str, str] | None = None) -> list[RouteTable]:
        """Convert raw Route Table data to a list of RouteTable objects for the specified region,
        optionally filtered by tags.

        This method takes the raw Route Table data obtained from the 'get_all_route_tables_raw' method,
        processes each Route Table's attributes, and converts them into a list of 'RouteTable' data
        class objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                          Route Tables based on tags. If None, retrieves all Route Tables.

        Returns:
            list[RouteTable]: A list of 'RouteTable' objects representing each Route Table in the specified
                              region.
        """
        route_tables = self.get_all_route_tables_raw(tags)
        route_table_objects = []

        for rt in route_tables:
            # Convert Routes
            routes = [
                Route(
                    destination_cidr_block=route.get("DestinationCidrBlock"),
                    destination_ipv6_cidr_block=route.get("DestinationIpv6CidrBlock"),
                    destination_prefix_list_id=route.get("DestinationPrefixListId"),
                    egress_only_internet_gateway_id=route.get("EgressOnlyInternetGatewayId"),
                    gateway_id=route.get("GatewayId"),
                    instance_id=route.get("InstanceId"),
                    instance_owner_id=route.get("InstanceOwnerId"),
                    nat_gateway_id=route.get("NatGatewayId"),
                    transit_gateway_id=route.get("TransitGatewayId"),
                    local_gateway_id=route.get("LocalGatewayId"),
                    carrier_gateway_id=route.get("CarrierGatewayId"),
                    network_interface_id=route.get("NetworkInterfaceId"),
                    origin=route.get("Origin"),
                    state=route.get("State"),
                    vpc_peering_connection_id=route.get("VpcPeeringConnectionId"),
                    core_network_arn=route.get("CoreNetworkArn")
                ) for route in rt.get("Routes", [])
            ]

            # Convert Associations
            associations = [
                RouteTableAssociation(
                    main=assoc.get("Main"),
                    route_table_association_id=assoc.get("RouteTableAssociationId", ""),
                    route_table_id=assoc.get("RouteTableId", ""),
                    subnet_id=assoc.get("SubnetId"),
                    gateway_id=assoc.get("GatewayId"),
                    association_state=assoc.get("AssociationState", {})
                ) for assoc in rt.get("Associations", [])
            ]

            # Convert tags to dictionary
            tags = {tag["Key"]: tag["Value"] for tag in rt.get("Tags", [])}

            # Create RouteTable object
            rt_obj = RouteTable(
                route_table_id=rt.get("RouteTableId", ""),
                vpc_id=rt.get("VpcId", ""),
                owner_id=rt.get("OwnerId", ""),
                routes=routes,
                associations=associations,
                propagating_vgws=rt.get("PropagatingVgws", []),
                tags=tags
            )
            route_table_objects.append(rt_obj)

        return route_table_objects
