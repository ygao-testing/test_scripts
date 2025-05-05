import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import SecurityGroup, SecurityGroupRule, UserIdGroupPair, IpRange, Ipv6Range, PrefixListId
from fortiqa.libs.aws.awshelper import AWSHelper

logger = logging.getLogger(__name__)


class SecurityGroupHelper(AWSHelper):
    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_security_groups_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve Security Group data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS EC2 'describe_security_groups' API to gather information about all
        Security Groups within the specified region. If tags are provided, only Security Groups with the
        specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                          Security Groups based on tags. If None, retrieves all Security Groups.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
                                  individual Security Group within the specified region.
        """
        logger.info(
            f"Retrieving Security Groups from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )
        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_security_groups(Filters=filters) if filters else self.client.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
        logger.debug(
            f"Security Group data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {security_groups}"
        )
        return security_groups

    def get_all_security_group_objects(self, tags: dict[str, str] | None = None) -> list[SecurityGroup]:
        """Convert raw Security Group data to a list of SecurityGroup objects for the specified region,
        optionally filtered by tags.

        This method takes the raw Security Group data obtained from the 'get_all_security_groups_raw' method,
        processes each Security Group's attributes, and converts them into a list of 'SecurityGroup' data
        class objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                          Security Groups based on tags. If None, retrieves all Security Groups.

        Returns:
            list[SecurityGroup]: A list of 'SecurityGroup' objects representing each Security Group in the specified
                                 region.
        """
        security_groups = self.get_all_security_groups_raw(tags)
        security_group_objects = []

        for sg in security_groups:
            # Convert IP permissions
            ip_permissions = [
                SecurityGroupRule(
                    ip_protocol=rule.get("IpProtocol", ""),
                    from_port=rule.get("FromPort"),
                    to_port=rule.get("ToPort"),
                    user_id_group_pairs=[
                        UserIdGroupPair(
                            user_id=pair.get("UserId"),
                            group_id=pair.get("GroupId")
                        ) for pair in rule.get("UserIdGroupPairs", [])
                    ],
                    ip_ranges=[
                        IpRange(
                            cidr_ip=ip_range.get("CidrIp"),
                            description=ip_range.get("Description")
                        ) for ip_range in rule.get("IpRanges", [])
                    ],
                    ipv6_ranges=[
                        Ipv6Range(
                            cidr_ipv6=ipv6_range.get("CidrIpv6"),
                            description=ipv6_range.get("Description")
                        ) for ipv6_range in rule.get("Ipv6Ranges", [])
                    ],
                    prefix_list_ids=[
                        PrefixListId(
                            prefix_list_id=prefix.get("PrefixListId"),
                            description=prefix.get("Description")
                        ) for prefix in rule.get("PrefixListIds", [])
                    ]
                ) for rule in sg.get("IpPermissions", [])
            ]

            # Convert IP permissions egress
            ip_permissions_egress = [
                SecurityGroupRule(
                    ip_protocol=rule.get("IpProtocol", ""),
                    from_port=rule.get("FromPort"),
                    to_port=rule.get("ToPort"),
                    user_id_group_pairs=[
                        UserIdGroupPair(
                            user_id=pair.get("UserId"),
                            group_id=pair.get("GroupId")
                        ) for pair in rule.get("UserIdGroupPairs", [])
                    ],
                    ip_ranges=[
                        IpRange(
                            cidr_ip=ip_range.get("CidrIp"),
                            description=ip_range.get("Description")
                        ) for ip_range in rule.get("IpRanges", [])
                    ],
                    ipv6_ranges=[
                        Ipv6Range(
                            cidr_ipv6=ipv6_range.get("CidrIpv6"),
                            description=ipv6_range.get("Description")
                        ) for ipv6_range in rule.get("Ipv6Ranges", [])
                    ],
                    prefix_list_ids=[
                        PrefixListId(
                            prefix_list_id=prefix.get("PrefixListId"),
                            description=prefix.get("Description")
                        ) for prefix in rule.get("PrefixListIds", [])
                    ]
                ) for rule in sg.get("IpPermissionsEgress", [])
            ]

            # Convert tags to dictionary
            tags = {tag["Key"]: tag["Value"] for tag in sg.get("Tags", [])}

            # Create SecurityGroup object
            sg_obj = SecurityGroup(
                group_id=sg.get("GroupId", ""),
                group_name=sg.get("GroupName", ""),
                description=sg.get("Description"),
                vpc_id=sg.get("VpcId"),
                owner_id=sg.get("OwnerId"),
                ip_permissions=ip_permissions,
                ip_permissions_egress=ip_permissions_egress,
                tags=tags
            )
            security_group_objects.append(sg_obj)

        return security_group_objects
