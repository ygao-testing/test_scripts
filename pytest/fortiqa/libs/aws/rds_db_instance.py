import logging
from typing import Any
from fortiqa.libs.aws.data_class.rds_data_classes import DBInstance, DBEndpoint, DBParameterGroup, OptionGroupMembership, CertificateDetails, DBSubnet, DBSubnetGroup, VpcSecurityGroup, DomainMembership, AssociatedRole
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601, datetime_to_iso8601_preserve_original_precision
from fortiqa.tests import settings


logger = logging.getLogger(__name__)


class RdsDbInstanceHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='rds', region=region, aws_credentials=aws_credentials)

    def get_all_rds_db_instances_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw RDS DB instance data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS RDS 'describe_db_instances' API to gather information about all
        RDS DB instances owned by the current account within the specified region. If tags are provided,
        only instances with the specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        DB instances based on tags. If None, retrieves all DB instances.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
                                individual RDS DB instance within the specified region.
        """
        logger.info(
            f"Retrieving RDS DB Instances from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )
        response = self.client.describe_db_instances()
        db_instances = response.get("DBInstances", [])

        if tags:
            filtered_instances = []
            for db_instance in db_instances:
                instance_arn = db_instance["DBInstanceArn"]
                tag_response = self.client.list_tags_for_resource(
                    ResourceName=instance_arn)
                instance_tags = {tag["Key"]: tag["Value"]
                                 for tag in tag_response.get("TagList", [])}

                if all(instance_tags.get(key) == value for key, value in tags.items()):
                    filtered_instances.append(db_instance)

            db_instances = filtered_instances

        logger.debug(
            f"RDS DB Instance data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {db_instances}"
        )
        return db_instances

    def get_all_rds_db_instance_objects(self, tags: dict[str, str] | None = None) -> list[DBInstance]:
        """Convert raw RDS instance data to a list of `DBInstance` objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering RDS instances.

        Returns:
            list[DBInstance]: A list of `DBInstance` objects.
        """
        raw_instances = self.get_all_rds_db_instances_raw(tags)
        rds_instance_objects = []

        for instance in raw_instances:
            logger.debug(f"Converting raw RDS instance data: {instance}")

            # Convert DBSubnetGroup
            db_subnet_group = None
            if instance.get("DBSubnetGroup"):
                db_subnet_group_data = instance["DBSubnetGroup"]
                subnets = [
                    DBSubnet(
                        subnet_identifier=subnet["SubnetIdentifier"],
                        availability_zone=subnet["SubnetAvailabilityZone"]["Name"],
                        status=subnet["SubnetStatus"]
                    ) for subnet in db_subnet_group_data.get("Subnets", [])
                ]
                db_subnet_group = DBSubnetGroup(
                    db_subnet_group_name=db_subnet_group_data["DBSubnetGroupName"],
                    db_subnet_group_description=db_subnet_group_data["DBSubnetGroupDescription"],
                    vpc_id=db_subnet_group_data["VpcId"],
                    subnet_group_status=db_subnet_group_data["SubnetGroupStatus"],
                    subnets=subnets
                )

            # Create DBInstance object
            rds_instance = DBInstance(
                account_id=settings.app.aws_account.aws_account_id,
                db_instance_identifier=instance["DBInstanceIdentifier"],
                db_instance_class=instance["DBInstanceClass"],
                engine=instance["Engine"],
                db_instance_status=instance["DBInstanceStatus"],
                master_username=instance.get("MasterUsername"),
                db_name=instance.get("DBName"),
                endpoint=DBEndpoint(
                    address=instance["Endpoint"]["Address"],
                    port=instance["Endpoint"]["Port"],
                    hosted_zone_id=instance["Endpoint"]["HostedZoneId"]
                ) if instance.get("Endpoint") else None,
                allocated_storage=instance["AllocatedStorage"],
                instance_create_time=datetime_to_iso8601(
                    instance["InstanceCreateTime"]),
                preferred_backup_window=instance["PreferredBackupWindow"],
                backup_retention_period=instance["BackupRetentionPeriod"],
                db_security_groups=instance.get("DBSecurityGroups", []),
                availability_zone=instance["AvailabilityZone"],
                db_subnet_group=db_subnet_group,
                preferred_maintenance_window=instance["PreferredMaintenanceWindow"],
                pending_modified_values=instance.get(
                    "PendingModifiedValues", {}),
                multi_az=instance["MultiAZ"],
                engine_version=instance["EngineVersion"],
                auto_minor_version_upgrade=instance["AutoMinorVersionUpgrade"],
                license_model=instance["LicenseModel"],
                read_replica_db_instance_identifiers=instance.get(
                    "ReadReplicaDBInstanceIdentifiers", []),
                publicly_accessible=instance["PubliclyAccessible"],
                storage_type=instance["StorageType"],
                db_instance_port=instance["DbInstancePort"],
                storage_encrypted=instance["StorageEncrypted"],
                dbi_resource_id=instance["DbiResourceId"],
                domain_memberships=[
                    DomainMembership(
                        domain=membership["Domain"],
                        status=membership["Status"],
                        fqdn=membership.get("FQDN"),
                        iam_role_name=membership.get("IAMRoleName")
                    ) for membership in instance.get("DomainMemberships", [])
                ],
                copy_tags_to_snapshot=instance["CopyTagsToSnapshot"],
                monitoring_interval=instance["MonitoringInterval"],
                db_instance_arn=instance["DBInstanceArn"],
                iam_database_authentication_enabled=instance["IAMDatabaseAuthenticationEnabled"],
                performance_insights_enabled=instance["PerformanceInsightsEnabled"],
                deletion_protection=instance["DeletionProtection"],
                max_allocated_storage=instance["MaxAllocatedStorage"],
                activity_stream_status=instance["ActivityStreamStatus"],
                backup_target=instance["BackupTarget"],
                network_type=instance["NetworkType"],
                storage_throughput=instance.get("StorageThroughput", 0),
                dedicated_log_volume=instance["DedicatedLogVolume"],
                engine_lifecycle_support=instance.get(
                    "EngineLifecycleSupport"),
                vpc_security_groups=[
                    VpcSecurityGroup(
                        vpc_security_group_id=sg["VpcSecurityGroupId"],
                        status=sg["Status"]
                    ) for sg in instance.get("VpcSecurityGroups", [])
                ],
                db_parameter_groups=[
                    DBParameterGroup(
                        db_parameter_group_name=pg["DBParameterGroupName"],
                        parameter_apply_status=pg["ParameterApplyStatus"]
                    ) for pg in instance.get("DBParameterGroups", [])
                ],
                option_group_memberships=[
                    OptionGroupMembership(
                        option_group_name=og["OptionGroupName"],
                        status=og["Status"]
                    ) for og in instance.get("OptionGroupMemberships", [])
                ],
                associated_roles=[
                    AssociatedRole(
                        role_arn=role["RoleArn"],
                        status=role["Status"],
                        feature_name=role.get("FeatureName")
                    ) for role in instance.get("AssociatedRoles", [])
                ],
                tags={tag["Key"]: tag["Value"]
                      for tag in instance.get("TagList", [])},
                certificate_details=CertificateDetails(
                    ca_identifier=instance["CertificateDetails"]["CAIdentifier"],
                    valid_till=datetime_to_iso8601_preserve_original_precision(
                        instance["CertificateDetails"]["ValidTill"])
                ) if instance.get("CertificateDetails") else None,
                is_storage_config_upgrade_available=instance.get(
                    "IsStorageConfigUpgradeAvailable", None),
                customer_owned_ip_enabled=instance["CustomerOwnedIpEnabled"]

            )

            rds_instance_objects.append(rds_instance)

        return rds_instance_objects
