from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class DBEndpoint:
    address: str
    port: int
    hosted_zone_id: str


@dataclass
class VpcSecurityGroup:
    vpc_security_group_id: str
    status: str


@dataclass
class DBParameterGroup:
    db_parameter_group_name: str
    parameter_apply_status: str


@dataclass
class DBSubnet:
    subnet_identifier: str
    availability_zone: str
    status: str


@dataclass
class DBSubnetGroup:
    db_subnet_group_name: str
    db_subnet_group_description: str
    vpc_id: str
    subnet_group_status: str
    subnets: list[DBSubnet]


@dataclass
class OptionGroupMembership:
    option_group_name: str
    status: str


@dataclass
class CertificateDetails:
    ca_identifier: str
    valid_till: str  # ISO 8601 formatted string


@dataclass
class DomainMembership:
    domain: str
    status: str
    fqdn: Optional[str] = None
    iam_role_name: Optional[str] = None
    ou: Optional[str] = None
    auth_secret_arn: Optional[str] = None
    dns_ips: list[str] = field(default_factory=list)


@dataclass
class AssociatedRole:
    role_arn: str
    status: str
    feature_name: Optional[str] = None


@dataclass
class DBInstance:
    account_id: str  # Added account ID
    db_instance_identifier: str
    db_instance_class: str
    engine: str
    db_instance_status: str
    allocated_storage: int
    instance_create_time: str  # ISO 8601 formatted string
    preferred_backup_window: str
    backup_retention_period: int
    availability_zone: str
    preferred_maintenance_window: str
    multi_az: bool
    engine_version: str
    auto_minor_version_upgrade: bool
    license_model: str
    publicly_accessible: bool
    storage_type: str
    db_instance_port: int
    storage_encrypted: bool
    dbi_resource_id: str
    db_instance_arn: str
    iam_database_authentication_enabled: bool
    performance_insights_enabled: bool
    deletion_protection: bool
    max_allocated_storage: int
    activity_stream_status: str
    backup_target: str
    network_type: str
    storage_throughput: int
    dedicated_log_volume: bool
    copy_tags_to_snapshot: bool
    monitoring_interval: int
    db_security_groups: list[str] = field(default_factory=list)
    master_username: Optional[str] = None
    db_name: Optional[str] = None
    endpoint: Optional[DBEndpoint] = None
    db_subnet_group: Optional[DBSubnetGroup] = None
    pending_modified_values: dict[str, Any] = field(default_factory=dict)
    read_replica_db_instance_identifiers: list[str] = field(
        default_factory=list)
    domain_memberships: list[DomainMembership] = field(default_factory=list)
    associated_roles: list[AssociatedRole] = field(default_factory=list)
    engine_lifecycle_support: Optional[str] = None
    vpc_security_groups: list[VpcSecurityGroup] = field(default_factory=list)
    db_parameter_groups: list[DBParameterGroup] = field(default_factory=list)
    option_group_memberships: list[OptionGroupMembership] = field(
        default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)  # Tags as a dictionary
    certificate_details: Optional[CertificateDetails] = None
    customer_owned_ip_enabled: bool = False
    is_storage_config_upgrade_available: Optional[bool] = None
