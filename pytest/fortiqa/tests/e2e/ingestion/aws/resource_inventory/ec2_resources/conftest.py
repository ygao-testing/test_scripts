import pytest
import logging
from fortiqa.libs.aws.ec2 import EC2Helper
from fortiqa.libs.aws.vpc import VpcHelper
from fortiqa.libs.aws.data_class.ec2_data_classes import Ec2Instance, VPC, InternetGateway, NatGateway, Volume, Snapshot, SecurityGroup, RouteTable
from fortiqa.libs.aws.internet_gateway import InternetGatewayHelper
from fortiqa.libs.aws.nat_gateway import NatGatewayHelper
from fortiqa.libs.aws.ec2_volume import Ec2VolumeHelper
from fortiqa.libs.aws.ec2_snapshot import Ec2SnapshotHelper
from fortiqa.libs.aws.security_group import SecurityGroupHelper
from fortiqa.libs.aws.route_table import RouteTableHelper
from fortiqa.libs.helper.general_helper import select_random_from_list
logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_aws_ec2_instances(aws_region, aws_account, ingestion_tag) -> list[Ec2Instance]:
    """Retrieve all EC2 instances for a specified AWS region, optionally filtered by a tag.

    This fixture uses the 'aws_region' fixture to determine the AWS region and the 'aws_account' fixture
    for authentication credentials. It utilizes an instance of 'EC2Helper' to fetch EC2 instances in
    the specified region. If an 'ingestion_tag' is provided, only instances matching the tag are retrieved.
    Otherwise, all EC2 instances in the region are returned.

    Args:
        aws_region (str): The AWS region to retrieve EC2 instances from, provided by the 'aws_region' fixture.
        aws_account (AWSAccount): A data class containing AWS credentials such as 'aws_access_key_id',
                                  'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag (dict[str, str]): Optional tag used to filter resources. If provided, only instances
                                        matching the tag are retrieved.

    Returns:
        list[Ec2Instance]: A list of 'Ec2Instance' objects representing all EC2 instances found in the
                           specified region that match the optional 'ingestion_tag'.
    """
    logger.info(f"Find all EC2 instances in region: {aws_region}'{
                f', with tags  {ingestion_tag}' if ingestion_tag else ''}")
    aws_region
    ec2_helper = EC2Helper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_ec2_instance = ec2_helper.get_all_ec2_instances(ingestion_tag)
    if all_ec2_instance:
        logger.info(f"All Ec2 Instances for region {aws_region}{f', with tags {
                    ingestion_tag}' if ingestion_tag else ''}:\n{all_ec2_instance}")
    else:
        logger.info(f"There is no EC2 instances for region: {aws_region}{
                    f', with tags  {ingestion_tag}' if ingestion_tag else ''}")
    return all_ec2_instance


@pytest.fixture(scope='session')
def random_ec2_instance(all_aws_ec2_instances, aws_region) -> Ec2Instance | None:
    """Fixture to select a random EC2 instance from the provided list of EC2 instance objects.

    Args:
        all_aws_ec2_instances : A list of 'Ec2Instance' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        Ec2Instance | None: A randomly selected 'Ec2Instance' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_ec2_instances, f"EC2 instances in region {aws_region}")


@pytest.fixture(scope='session')
def ec2_instance_with_public_ip(all_aws_ec2_instances, aws_region) -> Ec2Instance | None:
    """Fixture to select a random EC2 instance with a public IP address from the provided list of EC2 instances.

    Args:
        all_aws_ec2_instances :  a list of 'Ec2Instance' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        Ec2Instance | None : A randomly selected EC2 instance with a public IP address or None if no such instance exists.
    """
    instances_with_public_ip = [
        instance for instance in all_aws_ec2_instances if instance.public_ip_address is not None]
    return select_random_from_list(instances_with_public_ip, f"EC2 instances with public IP in region {aws_region}")


@pytest.fixture(scope='session')
def ec2_instance_with_security_group(all_aws_ec2_instances, aws_region) -> Ec2Instance | None:
    """Fixture to select a random EC2 instance with at least one security group from the provided list.

    Args:
        all_aws_ec2_instances :  a list of 'Ec2Instance' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
       Ec2Instance | None, str: A randomly selected 'Ec2Instance' with security groups or None if no such instance is available.
    """
    # Filter instances that have security groups defined (non-empty list)

    instances_with_security_groups = [
        instance for instance in all_aws_ec2_instances if instance.security_groups]
    return select_random_from_list(instances_with_security_groups, f"EC2 instances with security groups in region {aws_region}")


@pytest.fixture(scope='session')
def ec2_instance_with_private_ip_address(all_aws_ec2_instances, aws_region) -> Ec2Instance | None:
    """Fixture to select a random EC2 instance with a private IP address from the provided list.

    Args:
        all_aws_ec2_instances :  a list of 'Ec2Instance' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        Ec2Instance | None: A randomly selected 'Ec2Instance' with a private IP or None if no such instance is available.
    """
    instance_with_private_ip = [
        instance for instance in all_aws_ec2_instances if instance.private_ip_address]
    return select_random_from_list(instance_with_private_ip, f"EC2 instances with private IP in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_vpcs_region(aws_region, aws_account, ingestion_tag) -> list[VPC]:
    """Retrieves all VPCs for a specified AWS region, optionally filtering by ingestion tags.

        This fixture uses the 'aws_region' fixture to determine the region for which
        to retrieve VPCs. It utilizes AWS credentials provided by the 'aws_account'
        fixture to create an instance of 'EC2Helper', which fetches all VPCs
        in the specified region.
        If 'ingestion_tag' is provided, only VPCs with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve VPCs from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                    'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[VPC]: A list of 'VPC' objects representing all VPCs found in the specified region,
                optionally filtered by the specified tags.
    """
    logger.info(f"Find all VPCs in region: {aws_region}'{
                f', with tags  {ingestion_tag}' if ingestion_tag else ''}")
    vpc_helper = VpcHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_vpcs_objs = vpc_helper.get_all_vpc_objects(tags=ingestion_tag)

    if all_vpcs_objs:
        logger.info(f"All VPCs for region {aws_region}{f', with tags {
                    ingestion_tag}' if ingestion_tag else ''}:\n{all_vpcs_objs}")
    else:
        logger.info(f"There are no VPCs for region {aws_region}{
                    f', with tags  {ingestion_tag}' if ingestion_tag else ''}")

    return all_vpcs_objs


@pytest.fixture(scope='session')
def random_vpc(all_aws_vpcs_region, aws_region) -> VPC | None:
    """Fixture to select a random VPC from the provided list of VPC objects.

    Args:
        all_aws_vpcs_regio : A list of 'VPC' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        VPC | None: A randomly selected 'VPC' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_vpcs_region, f"VPC in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_internet_gateways_region(aws_region, aws_account, ingestion_tag) -> list[InternetGateway]:
    """Retrieves all internet gateways for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve internet gateways. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'InternetGatewayHelper', which fetches all internet gateways
    in the specified region. If 'ingestion_tag' is provided, only internet gateways with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve internet gateways from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[InternetGateway]: A list of 'InternetGateway' objects representing all internet gateways found in the specified region,
                               optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all Internet Gateways in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    igw_helper = InternetGatewayHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_igw_objs = igw_helper.get_all_internet_gateway_objects(ingestion_tag)
    if all_igw_objs:
        logger.info(
            f"All Internet Gateways for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_igw_objs}"
        )
    else:
        logger.info(f"There are no Internet Gateways for region: {aws_region}{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_igw_objs


@pytest.fixture(scope='session')
def random_internet_gateway(all_aws_internet_gateways_region, aws_region) -> InternetGateway | None:
    """Fixture to select a random internet gateway from the provided list of internet gateway objects.

    Args:
        all_aws_internet_gateways_region : A list of 'InternetGateway' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        InternetGateway | None: A randomly selected 'InternetGateway' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_internet_gateways_region, f"Internet Gateways in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_nat_gateways_region(aws_region, aws_account, ingestion_tag) -> list[NatGateway]:
    """Retrieves all NAT Gateways for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve NAT Gateways. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'NatGatewayHelper', which fetches all NAT Gateways
    in the specified region. If 'ingestion_tag' is provided, only NAT Gateways with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve NAT Gateways from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[NatGateway]: A list of 'NatGateway' objects representing all NAT Gateways found in the specified region,
                          optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all NAT Gateways in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    nat_gateway_helper = NatGatewayHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_nat_gateways = nat_gateway_helper.get_all_nat_gateway_objects(
        ingestion_tag)
    if all_nat_gateways:
        logger.info(
            f"All NAT Gateways for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_nat_gateways}"
        )
    else:
        logger.info(f"There are no NAT Gateway for region: {aws_region}{
                    f', with tags  {ingestion_tag}' if ingestion_tag else ''}")
    return all_nat_gateways


@pytest.fixture(scope='session')
def random_nat_gateway(all_aws_nat_gateways_region, aws_region) -> NatGateway | None:
    """Fixture to select a random NAT Gateway from the provided list of NAT Gateway objects.

    Args:
        all_aws_nat_gateways_region : A list of 'NatGateway' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        NatGateway | None: A randomly selected 'NatGateway' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_nat_gateways_region, f"NAT Gateways in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_volumes_region(aws_region, aws_account, ingestion_tag) -> list[Volume]:
    """Retrieves all EC2 Volumes for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve EC2 Volumes. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'Ec2VolumeHelper', which fetches all EC2 Volumes
    in the specified region. If 'ingestion_tag' is provided, only volumes with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve EC2 Volumes from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[Volume]: A list of 'Volume' objects representing all EC2 Volumes found in the specified region,
                      optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all EC2 Volumes in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    ec2_volume_helper = Ec2VolumeHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_volumes = ec2_volume_helper.get_all_volume_objects(ingestion_tag)
    if all_volumes:
        logger.info(
            f"All EC2 Volumes for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_volumes}"
        )
    else:
        logger.info(f"There are no EC2 Volumes for region: {aws_region}{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_volumes


@pytest.fixture(scope='session')
def random_volume(all_aws_volumes_region, aws_region) -> Volume | None:
    """Fixture to select a random EC2 Volume from the provided list of Volume objects.

    Args:
        all_aws_volumes_region : A list of 'Volume' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        Volume | None: A randomly selected 'Volume' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_volumes_region, f"EC2 Volumes in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_snapshots_region(aws_region, aws_account, ingestion_tag) -> list[Snapshot]:
    """Retrieves all EC2 Snapshots for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve EC2 Snapshots. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'Ec2SnapshotHelper', which fetches all EC2 Snapshots
    in the specified region. If 'ingestion_tag' is provided, only Snapshots with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve EC2 Snapshots from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[Snapshot]: A list of 'Snapshot' objects representing all EC2 Snapshots found in the specified region,
                        optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all EC2 Snapshots in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    snapshot_helper = Ec2SnapshotHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_snapshots = snapshot_helper.get_all_snapshot_objects(ingestion_tag)
    if all_snapshots:
        logger.info(
            f"All EC2 Snapshots for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_snapshots}"
        )
    else:
        logger.info(f"There are no EC2 Snapshots for region: {aws_region}{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_snapshots


@pytest.fixture(scope='session')
def random_snapshot(all_aws_snapshots_region, aws_region) -> Snapshot | None:
    """Fixture to select a random EC2 Snapshot from the provided list of Snapshot objects.

    Args:
        all_aws_snapshots_region : A list of 'Snapshot' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        Snapshot | None: A randomly selected 'Snapshot' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_snapshots_region, f"EC2 Snapshots in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_security_groups_region(aws_region, aws_account, ingestion_tag) -> list[SecurityGroup]:
    """Retrieves all Security Groups for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve Security Groups. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'SecurityGroupHelper', which fetches all Security Groups
    in the specified region. If 'ingestion_tag' is provided, only Security Groups with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve Security Groups from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[SecurityGroup]: A list of 'SecurityGroup' objects representing all Security Groups found in the specified region,
                             optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all Security Groups in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    security_group_helper = SecurityGroupHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_security_groups = security_group_helper.get_all_security_group_objects(
        ingestion_tag)
    if all_security_groups:
        logger.info(
            f"All Security Groups for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_security_groups}"
        )
    else:
        logger.info(f"There are no Security Groups for region: {aws_region}{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_security_groups


@pytest.fixture(scope='session')
def random_security_group(all_aws_security_groups_region, aws_region) -> SecurityGroup | None:
    """Fixture to select a random Security Group from the provided list of Security Group objects.

    Args:
        all_aws_security_groups_region : A list of 'SecurityGroup' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        SecurityGroup | None: A randomly selected 'SecurityGroup' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_security_groups_region, f"Security Groups in region {aws_region}")


@pytest.fixture(scope='session')
def all_aws_route_tables_region(aws_region, aws_account, ingestion_tag) -> list[RouteTable]:
    """Retrieves all Route Tables for a specified AWS region, optionally filtering by ingestion tags.

    This fixture uses the 'aws_region' fixture to determine the region for which
    to retrieve Route Tables. It utilizes AWS credentials provided by the 'aws_account'
    fixture to create an instance of 'RouteTableHelper', which fetches all Route Tables
    in the specified region. If 'ingestion_tag' is provided, only Route Tables with the specified tags are included.

    Args:
        aws_region: The AWS region to retrieve Route Tables from, provided by the 'aws_region' fixture.
        aws_account: A data class containing AWS credentials such as 'aws_access_key_id',
                     'aws_secret_access_key', and 'aws_account_id'.
        ingestion_tag: A dictionary containing the tag key-value pair for filtering resources.

    Returns:
        list[RouteTable]: A list of 'RouteTable' objects representing all Route Tables found in the specified region,
                          optionally filtered by the specified tags.
    """
    logger.info(
        f"Finding all Route Tables in region: {aws_region}"
        f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}"
    )
    route_table_helper = RouteTableHelper(
        region=aws_region, aws_credentials=aws_account.credentials)
    all_route_tables = route_table_helper.get_all_route_table_objects(
        ingestion_tag)
    if all_route_tables:
        logger.info(
            f"All Route Tables for region {aws_region}"
            f"{f', with tags {ingestion_tag}' if ingestion_tag else ''}:\n{
                all_route_tables}"
        )
    else:
        logger.info(f"There are no Route Tables for region: {aws_region}{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
    return all_route_tables


@pytest.fixture(scope='session')
def random_route_table(all_aws_route_tables_region, aws_region) -> RouteTable | None:
    """Fixture to select a random Route Table from the provided list of Route Table objects.

    Args:
        all_aws_route_tables_region : A list of 'RouteTable' objects.
        aws_region : AWS region provided by the 'aws_region' fixture.

    Returns:
        RouteTable | None: A randomly selected 'RouteTable' object or None if the list is empty.
    """
    return select_random_from_list(all_aws_route_tables_region, f"Route Tables in region {aws_region}")
