from dataclasses import dataclass, field
from typing import Optional


@dataclass
class State:
    code: int
    name: str


@dataclass
class Ec2SecurityGroup:
    group_id: str
    group_name: str


@dataclass
class CpuOptions:
    core_count: int
    threads_per_core: int


@dataclass
class EnclaveOptions:
    enabled: bool


@dataclass
class HibernationOptions:
    configured: bool


@dataclass
class Ec2Instance:
    instance_id: str
    image_id: str
    instance_type: str
    architecture: str
    hypervisor: str
    virtualization_type: str
    state: State
    private_dns_name: str
    public_dns_name: str
    launch_time: str
    subnet_id: str
    vpc_id: str
    region: str
    account_id: str
    private_ip_address: str
    public_ip_address: Optional[str]
    platform_details: str
    usage_operation: str
    usage_operation_update_time: str
    cpu_options: CpuOptions
    ebs_optimized: bool
    ena_support: bool
    enclave_options: EnclaveOptions
    hibernation_options: HibernationOptions
    security_groups: list[Ec2SecurityGroup] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class S3Bucket:
    name: str
    creation_date: str  # Store as formatted string
    account_id: str


@dataclass
class CidrBlockAssociation:
    association_id: str
    cidr_block: str
    cidr_block_state: dict[str, str]


@dataclass
class VPC:
    account_id: str
    owner_id: str
    instance_tenancy: str
    cidr_block_association_set: list[CidrBlockAssociation]
    is_default: bool
    vpc_id: str
    state: str
    cidr_block: str
    dhcp_options_id: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Attachment:
    state: str
    vpc_id: str


@dataclass
class InternetGateway:
    account_id: str
    internet_gateway_id: str
    owner_id: str
    attachments: list[Attachment] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class NatGatewayAddress:
    allocation_id: str
    network_interface_id: str
    private_ip: str
    public_ip: str
    association_id: str
    is_primary: bool
    status: str


@dataclass
class NatGateway:
    nat_gateway_id: str
    account_id: str
    create_time: str
    state: str
    subnet_id: str
    vpc_id: str
    connectivity_type: str
    nat_gateway_addresses: list[NatGatewayAddress] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class VolumeAttachment:
    delete_on_termination: bool
    volume_id: str
    instance_id: str
    device: str
    state: str
    attach_time: str  # ISO 8601 formatted string


@dataclass
class Volume:
    volume_id: str
    account_id: str
    iops: int
    size: int
    snapshot_id: Optional[str]  # SnapshotId is optional or empty
    availability_zone: str
    state: str
    create_time: str  # ISO 8601 formatted string
    volume_type: str
    multi_attach_enabled: bool
    encrypted: bool
    throughput: Optional[int] = None  # Only applicable for certain volume types (e.g., gp3)
    attachments: list[VolumeAttachment] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Snapshot:
    snapshot_id: str
    account_id: str
    volume_id: str
    state: str
    start_time: str  # ISO 8601 formatted string
    progress: str
    owner_id: str
    description: str
    volume_size: int
    encrypted: bool
    storage_tier: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class UserIdGroupPair:
    """Represents user group pair in security group rules."""
    user_id: Optional[str] = None
    group_id: Optional[str] = None


@dataclass
class IpRange:
    """Represents an IPv4 range in security group rules."""
    cidr_ip: Optional[str] = None
    description: Optional[str] = None


@dataclass
class Ipv6Range:
    """Represents an IPv6 range in security group rules."""
    cidr_ipv6: Optional[str] = None
    description: Optional[str] = None


@dataclass
class PrefixListId:
    """Represents a prefix list in security group rules."""
    prefix_list_id: Optional[str] = None
    description: Optional[str] = None


@dataclass
class SecurityGroupRule:
    """Represents an individual rule in a security group."""
    ip_protocol: str
    from_port: Optional[int] = None
    to_port: Optional[int] = None
    user_id_group_pairs: list[UserIdGroupPair] = field(default_factory=list)
    ip_ranges: list[IpRange] = field(default_factory=list)
    ipv6_ranges: list[Ipv6Range] = field(default_factory=list)
    prefix_list_ids: list[PrefixListId] = field(default_factory=list)


@dataclass
class SecurityGroup:
    """Represents a security group."""
    group_id: str
    group_name: str
    description: Optional[str] = None
    vpc_id: Optional[str] = None
    owner_id: Optional[str] = None
    ip_permissions: list[SecurityGroupRule] = field(default_factory=list)
    ip_permissions_egress: list[SecurityGroupRule] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class RouteTableAssociation:
    """Represents an association between a route table and a subnet or VPC."""
    route_table_association_id: str
    route_table_id: str
    main: Optional[bool] = None
    subnet_id: Optional[str] = None
    gateway_id: Optional[str] = None
    association_state: Optional[dict[str, str]] = field(default_factory=dict)


@dataclass
class Route:
    """Represents a route in a route table."""
    destination_cidr_block: Optional[str] = None
    destination_ipv6_cidr_block: Optional[str] = None
    destination_prefix_list_id: Optional[str] = None
    egress_only_internet_gateway_id: Optional[str] = None
    gateway_id: Optional[str] = None
    instance_id: Optional[str] = None
    instance_owner_id: Optional[str] = None
    nat_gateway_id: Optional[str] = None
    transit_gateway_id: Optional[str] = None
    local_gateway_id: Optional[str] = None
    carrier_gateway_id: Optional[str] = None
    network_interface_id: Optional[str] = None
    origin: Optional[str] = None
    state: Optional[str] = None
    vpc_peering_connection_id: Optional[str] = None
    core_network_arn: Optional[str] = None


@dataclass
class RouteTable:
    """Represents a route table."""
    route_table_id: str
    vpc_id: str
    owner_id: str
    routes: list[Route] = field(default_factory=list)
    associations: list[RouteTableAssociation] = field(default_factory=list)
    propagating_vgws: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
