import boto3
import logging
from typing import Dict, List, Any
from fortiqa.libs.aws.awshelper import AWSHelper

logger = logging.getLogger(__name__)


class AWSCleanupHelper(AWSHelper):
    """Helper class for cleaning up AWS resources that match any of the specified tags."""

    CLEANUP_TAGS = {
        'LWTAG_LACEWORK_AGENTLESS': '1',
        'lacework_tag': 'lacework-self-deploy'
    }

    def __init__(self, region: str = 'us-east-2', aws_credentials: Dict = {}):
        """Initialize AWS cleanup helper with necessary clients.

        Args:
            region: Default AWS region name (for services that require a region)
            aws_credentials: Optional dict with aws_access_key_id and aws_secret_access_key
        """
        super().__init__(boto3_client='s3', region=region, aws_credentials=aws_credentials)

        # Store credentials for resource creation
        self.aws_credentials = aws_credentials
        self.region = region

        # Initialize EC2 client for listing regions
        if aws_credentials:
            self.ec2 = boto3.client(
                'ec2',
                region_name=region,
                aws_access_key_id=aws_credentials['aws_access_key_id'],
                aws_secret_access_key=aws_credentials['aws_secret_access_key']
            )
        else:
            self.ec2 = boto3.client('ec2', region_name=region)

        # Get list of all available regions
        try:
            regions = self.ec2.describe_regions()['Regions']
            self.available_regions = [region['RegionName'] for region in regions]
            logger.info(f"Found {len(self.available_regions)} available AWS regions")
        except Exception as e:
            logger.error(f"Error getting AWS regions: {str(e)}")
            self.available_regions = [region]

    def _get_client(self, service: str, region: str) -> Any:
        """Create a boto3 client for the specified service and region.

        Args:
            service: AWS service name (e.g., 'ec2', 'ecs')
            region: AWS region name

        Returns:
            boto3 client
        """
        if self.aws_credentials:
            return boto3.client(
                service,
                region_name=region,
                aws_access_key_id=self.aws_credentials['aws_access_key_id'],
                aws_secret_access_key=self.aws_credentials['aws_secret_access_key']
            )
        return boto3.client(service, region_name=region)

    def _check_resource_tags(self, tags: List[Dict[str, str]]) -> bool:
        """Check if any of the resource tags match our cleanup tags.

        Args:
            tags: List of tag dictionaries, each containing 'key' (or 'Key') and 'value' (or 'Value')

        Returns:
            bool: True if any tag matches our cleanup criteria
        """
        if not tags:
            return False

        for tag in tags:
            # Handle both lowercase (ECS) and uppercase (S3) tag keys
            tag_key = tag.get('key', tag.get('Key'))
            tag_value = tag.get('value', tag.get('Value'))

            if tag_key in self.CLEANUP_TAGS and tag_value == self.CLEANUP_TAGS[tag_key]:
                return True
        return False

    def cleanup_s3_buckets(self, dry_run: bool = True) -> List[str]:
        """Find and delete S3 buckets that match any of the specified tags.
        S3 is a global service, so no need to iterate through regions.
        """
        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Looking for S3 buckets with specified tags")

        # Initialize S3 client (S3 is global, so region doesn't matter)
        if self.aws_credentials:
            self.s3 = boto3.client(
                's3',
                aws_access_key_id=self.aws_credentials['aws_access_key_id'],
                aws_secret_access_key=self.aws_credentials['aws_secret_access_key']
            )
        else:
            self.s3 = boto3.client('s3')

        buckets_to_delete = []

        # List all buckets
        response = self.s3.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            try:
                # Get bucket tagging
                tags = self.s3.get_bucket_tagging(Bucket=bucket_name)
                if self._check_resource_tags(tags.get('TagSet', [])):
                    buckets_to_delete.append(bucket_name)
            except self.s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchTagSet':
                    continue
                else:
                    logger.error(f"Error getting tags for bucket {bucket_name}: {str(e)}")
                    continue

        if not buckets_to_delete:
            logger.info("No S3 buckets found with the specified tags")
            return []

        logger.info(f"Found {len(buckets_to_delete)} S3 buckets to delete:")
        logger.info('\n'.join(buckets_to_delete))

        if dry_run:
            return buckets_to_delete

        remaining_buckets = buckets_to_delete[:]
        # Delete buckets
        for bucket_name in buckets_to_delete:
            try:
                # First, delete all objects and their versions in the bucket
                if self.aws_credentials:
                    s3_resource = boto3.resource(
                        's3',
                        aws_access_key_id=self.aws_credentials['aws_access_key_id'],
                        aws_secret_access_key=self.aws_credentials['aws_secret_access_key']
                    )
                else:
                    s3_resource = boto3.resource('s3')

                bucket = s3_resource.Bucket(bucket_name)

                # Delete all versions (including delete markers)
                bucket.object_versions.delete()

                # Delete remaining objects (if any)
                bucket.objects.all().delete()

                # Delete any bucket policy
                try:
                    self.s3.delete_bucket_policy(Bucket=bucket_name)
                except self.s3.exceptions.ClientError:
                    pass  # Ignore if no policy exists

                # Then delete the bucket
                self.s3.delete_bucket(Bucket=bucket_name)
                logger.info(f"Successfully deleted bucket: {bucket_name}")
                remaining_buckets.remove(bucket_name)
            except Exception as e:
                logger.error(f"Error deleting bucket {bucket_name}: {str(e)}")

        return remaining_buckets

    def cleanup_ecs_clusters(self, dry_run: bool = True) -> List[Dict[str, str]]:
        """Find and delete ECS clusters that match any of the specified tags across all regions."""
        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Looking for ECS clusters with specified tags")

        clusters_to_delete = []

        for region in self.available_regions:
            try:
                ecs_client = self._get_client('ecs', region)

                # List all clusters in this region
                response = ecs_client.list_clusters()
                cluster_arns = response.get('clusterArns', [])

                if not cluster_arns:
                    continue

                # Get details for each cluster
                clusters = ecs_client.describe_clusters(
                    clusters=cluster_arns,
                    include=['TAGS']
                )
                logger.info(f"Region: {region}, Clusters: {clusters['clusters']}")
                for cluster in clusters['clusters']:
                    if self._check_resource_tags(cluster.get('tags', [])):
                        clusters_to_delete.append({
                            'region': region,
                            'arn': cluster['clusterArn']
                        })
            except Exception as e:
                logger.error(f"Error listing ECS clusters in region {region}: {str(e)}")
                continue

        if not clusters_to_delete:
            logger.info("No ECS clusters found with the specified tags")
            return []

        logger.info(f"Found {len(clusters_to_delete)} ECS clusters to delete:")
        for cluster in clusters_to_delete:
            logger.info(f"Region: {cluster['region']}, ARN: {cluster['arn']}")

        if dry_run:
            return clusters_to_delete

        # Delete clusters
        remaining_clusters = clusters_to_delete[:]
        for cluster in clusters_to_delete:
            try:
                ecs_client = self._get_client('ecs', cluster['region'])

                # First, delete all services in the cluster
                services = ecs_client.list_services(cluster=cluster['arn'])
                if services.get('serviceArns'):
                    ecs_client.delete_services(cluster=cluster['arn'], services=services['serviceArns'], force=True)

                # Then delete the cluster
                ecs_client.delete_cluster(cluster=cluster['arn'])
                # logger.info(f"Successfully deleted cluster: {cluster['arn']} in region {cluster['region']}")
                remaining_clusters.remove(cluster)
            except Exception as e:
                logger.error(f"Error deleting cluster {cluster['arn']} in region {cluster['region']}: {str(e)}")
        logger.info(f"{len(clusters_to_delete) - len(remaining_clusters)} clusters deleted")
        return remaining_clusters

    def cleanup_ecs_task_definitions(self, dry_run: bool = True) -> List[Dict[str, str]]:
        """Find and deregister ECS task definitions that match any of the specified tags across all regions."""
        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Looking for ECS task definitions with specified tags")

        task_defs_to_delete = []

        for region in self.available_regions:
            try:
                ecs_client = self._get_client('ecs', region)

                # List all task definition families in this region
                response = ecs_client.list_task_definition_families()
                families = response.get('families', [])

                if not families:
                    continue

                # For each family, get active task definitions
                for family in families:
                    response = ecs_client.list_task_definitions(familyPrefix=family, status='ACTIVE')
                    task_def_arns = response.get('taskDefinitionArns', [])

                    for task_def_arn in task_def_arns:
                        try:
                            task_def = ecs_client.describe_task_definition(
                                taskDefinition=task_def_arn,
                                include=['TAGS']
                            )
                            logger.info(f"Region: {region}, ARN: {task_def_arn}, Tags: {task_def.get('tags', [])}")
                            if self._check_resource_tags(task_def.get('tags', [])):
                                task_defs_to_delete.append({
                                    'region': region,
                                    'arn': task_def_arn
                                })
                        except Exception as e:
                            logger.error(f"Error describing task definition {task_def_arn} in region {region}: {str(e)}")
                            continue

            except Exception as e:
                logger.error(f"Error listing task definitions in region {region}: {str(e)}")
                continue

        if not task_defs_to_delete:
            logger.info("No ECS task definitions found with the specified tags")
            return []

        logger.info(f"Found {len(task_defs_to_delete)} ECS task definitions to deregister:")
        for task_def in task_defs_to_delete:
            logger.info(f"Region: {task_def['region']}, ARN: {task_def['arn']}")

        if dry_run:
            return task_defs_to_delete

        # Deregister task definitions
        remaining_defs = task_defs_to_delete[:]
        for task_def in task_defs_to_delete:
            try:
                ecs_client = self._get_client('ecs', task_def['region'])
                ecs_client.deregister_task_definition(taskDefinition=task_def['arn'])
                logger.info(f"Successfully deregistered task definition: {task_def['arn']} in region {task_def['region']}")
                remaining_defs.remove(task_def)
            except Exception as e:
                logger.error(f"Error deregistering task definition {task_def['arn']} in region {task_def['region']}: {str(e)}")
        logger.info(f"total task defs {len(task_defs_to_delete)}, remaining {len(remaining_defs)}")
        return remaining_defs

    def cleanup_vpcs(self, dry_run: bool = True) -> List[Dict[str, str]]:
        """Find and delete VPCs that match any of the specified tags across all regions."""
        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Looking for VPCs with specified tags")

        vpcs_to_delete = []

        for region in self.available_regions:
            try:
                ec2_client = self._get_client('ec2', region)

                # Find VPCs with the specified tags in this region
                response = ec2_client.describe_vpcs(
                    Filters=[
                        {
                            'Name': f'tag:{tag_key}',
                            'Values': [tag_value]
                        } for tag_key, tag_value in self.CLEANUP_TAGS.items()
                    ]
                )

                for vpc in response.get('Vpcs', []):
                    vpcs_to_delete.append({
                        'region': region,
                        'id': vpc['VpcId']
                    })

            except Exception as e:
                logger.error(f"Error listing VPCs in region {region}: {str(e)}")
                continue

        if not vpcs_to_delete:
            logger.info("No VPCs found with the specified tags")
            return []

        logger.info(f"Found {len(vpcs_to_delete)} VPCs to delete:")
        for vpc in vpcs_to_delete:
            logger.info(f"Region: {vpc['region']}, ID: {vpc['id']}")

        if dry_run:
            return vpcs_to_delete

        # Delete VPCs and their dependencies
        successfully_deleted = []
        for vpc in vpcs_to_delete:
            try:
                ec2_client = self._get_client('ec2', vpc['region'])
                vpc_id = vpc['id']

                # 1. Terminate EC2 instances
                instances = ec2_client.describe_instances(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        if instance['State']['Name'] != 'terminated':
                            ec2_client.terminate_instances(InstanceIds=[instance['InstanceId']])
                            logger.info(f"Terminated instance {instance['InstanceId']} in region {vpc['region']}")
                            # Wait for instance termination
                            waiter = ec2_client.get_waiter('instance_terminated')
                            waiter.wait(InstanceIds=[instance['InstanceId']])

                # 2. Delete NAT Gateways
                nat_gateways = ec2_client.describe_nat_gateways(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for nat in nat_gateways.get('NatGateways', []):
                    if nat['State'] != 'deleted':
                        ec2_client.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                        logger.info(f"Deleted NAT Gateway {nat['NatGatewayId']} in region {vpc['region']}")
                        # Wait for NAT Gateway deletion
                        waiter = ec2_client.get_waiter('nat_gateway_available')
                        waiter.wait(NatGatewayIds=[nat['NatGatewayId']])

                # 3. Detach and delete Internet Gateways
                igws = ec2_client.describe_internet_gateways(
                    Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
                )
                for igw in igws.get('InternetGateways', []):
                    ec2_client.detach_internet_gateway(
                        InternetGatewayId=igw['InternetGatewayId'],
                        VpcId=vpc_id
                    )
                    ec2_client.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
                    logger.info(f"Deleted Internet Gateway {igw['InternetGatewayId']} in region {vpc['region']}")

                # 4. Delete Subnets
                subnets = ec2_client.describe_subnets(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for subnet in subnets.get('Subnets', []):
                    ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])
                    logger.info(f"Deleted Subnet {subnet['SubnetId']} in region {vpc['region']}")

                # 5. Delete non-main Route Tables
                route_tables = ec2_client.describe_route_tables(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for rt in route_tables.get('RouteTables', []):
                    # Skip main route table
                    if not any(assoc.get('Main', False) for assoc in rt.get('Associations', [])):
                        ec2_client.delete_route_table(RouteTableId=rt['RouteTableId'])
                        logger.info(f"Deleted Route Table {rt['RouteTableId']} in region {vpc['region']}")

                # 6. Delete non-default Network ACLs
                acls = ec2_client.describe_network_acls(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for acl in acls.get('NetworkAcls', []):
                    if not acl['IsDefault']:
                        ec2_client.delete_network_acl(NetworkAclId=acl['NetworkAclId'])
                        logger.info(f"Deleted Network ACL {acl['NetworkAclId']} in region {vpc['region']}")

                # 7. Delete non-default Security Groups
                sgs = ec2_client.describe_security_groups(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for sg in sgs.get('SecurityGroups', []):
                    if sg['GroupName'] != 'default':
                        ec2_client.delete_security_group(GroupId=sg['GroupId'])
                        logger.info(f"Deleted Security Group {sg['GroupId']} in region {vpc['region']}")

                # 8. Delete VPC Endpoints
                endpoints = ec2_client.describe_vpc_endpoints(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                for endpoint in endpoints.get('VpcEndpoints', []):
                    ec2_client.delete_vpc_endpoints(VpcEndpointIds=[endpoint['VpcEndpointId']])
                    logger.info(f"Deleted VPC Endpoint {endpoint['VpcEndpointId']} in region {vpc['region']}")

                # 9. Delete VPC Peering Connections
                peering_connections = ec2_client.describe_vpc_peering_connections(
                    Filters=[
                        {
                            'Name': 'requester-vpc-info.vpc-id',
                            'Values': [vpc_id]
                        }
                    ]
                )
                for pc in peering_connections.get('VpcPeeringConnections', []):
                    ec2_client.delete_vpc_peering_connection(
                        VpcPeeringConnectionId=pc['VpcPeeringConnectionId']
                    )
                    logger.info(f"Deleted VPC Peering Connection {pc['VpcPeeringConnectionId']} in region {vpc['region']}")

                # 10. Finally, delete the VPC
                ec2_client.delete_vpc(VpcId=vpc_id)
                logger.info(f"Successfully deleted VPC: {vpc_id} in region {vpc['region']}")
                successfully_deleted.append(vpc)

            except Exception as e:
                logger.error(f"Error deleting VPC {vpc['id']} in region {vpc['region']}: {str(e)}")
                continue

        return successfully_deleted
