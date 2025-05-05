import logging
import json
import time
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import Ec2Instance, State, Ec2SecurityGroup, CpuOptions, EnclaveOptions, HibernationOptions
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from fortiqa.tests import settings

info = logging.getLogger(__name__).info
debug = logging.getLogger(__name__).debug
error = logging.getLogger(__name__).error


class EC2Helper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_instance_info_by_vpc_id(self, aws_security_vpc_id):
        """
        Return detailed instance info under vpc ID
        :param aws_security_vpc_id: aws vpc ID under aws_access_key_id/aws_secret_access_key
        :return: instance info under vpc ID
        """
        res = self.client.describe_instances(Filters=[
            {
                'Name': 'vpc-id',
                'Values': [f'{aws_security_vpc_id}']
            }
        ])
        debug(json.dumps(res, indent=2, default=str))
        return res

    def stop_instance_by_name(self, stop_instances):
        """
        Function stops aws instances and returns stdout
        :param stop_instances: dict of instance names to stop i.e. {'InstanceA-name': 1, 'InstanceB-name': 1}
        :return stdout: stdout from running boto stop_instances() method
        """
        instances = []
        response = self.client.describe_instances()
        for r in response['Reservations']:
            for i in r['Instances']:
                if 'Tags' in i:
                    for tag in i['Tags']:
                        if tag['Key'] == 'Name' and stop_instances.get(tag['Value']):
                            logging.info(f"Instance ID of {tag['Value']} is {i['InstanceId']}")
                            instances.append(i['InstanceId'])

        stdout = self.client.stop_instances(InstanceIds=instances)
        return stdout

    def start_instance_by_name(self, start_instances):
        """
        Function starts aws instances and returns the public ip addresses
        :param start_instances: dict of instance names to start i.e. {'InstanceA-name': 1, 'InstanceB-name': 1}
        :return public_ip: dict of instances public ip addresses
        """
        public_ip = {}
        response = self.client.describe_instances()
        for r in response['Reservations']:
            for i in r['Instances']:
                instances = []
                if 'Tags' in i:
                    for tag in i['Tags']:
                        if tag['Key'] == 'Name' and start_instances.get(tag['Value']):
                            logging.info(
                                f"Instance ID of {tag['Value']}"
                                f" is {i['InstanceId']}"
                            )
                            instances.append(i['InstanceId'])
                            self.client.start_instances(InstanceIds=instances)

                            running_state = 0
                            while not running_state:
                                response = self.client.describe_instance_status(
                                    InstanceIds=instances)['InstanceStatuses']
                                if response:
                                    if response[0]['InstanceState']['Name'] == "running":
                                        running_state = 1
                                        logging.info(
                                            f"Instance {tag['Value']} is running")
                                        ip = self.client.describe_instances(InstanceIds=instances)[
                                            'Reservations'][0]['Instances'][0]['PublicIpAddress']
                                        logging.info(
                                            "Public IP address of instance"
                                            f" {tag['Value']} is {ip}"
                                        )
                                        public_ip[tag['Value']] = ip
        return public_ip

    def get_vpc_resourcegroup_name_by_popname(self, tag_popname):
        """Return vpc's resource group name based on tag popname to form autoscaling group name

        :param tag_popname: aws vpc tag popname
        :return: vpc resource group name
        """
        vpc_id = self.get_vpc_id_by_tag_popname(tag_popname=tag_popname)

        res = self.client.describe_vpcs(
            VpcIds=[
                vpc_id,
            ]
        )
        debug(json.dumps(res, indent=2, default=str))

        if res['Vpcs']:
            values = filter(lambda x: x["Key"] ==
                            'ResourceGroup', res['Vpcs'][0]['Tags'])
            value = list(values)[0]
            return value["Value"]
        else:
            return ""

    def get_subnet_cidrblock_by_tag_name_vpc_id(self, tag_name, vpc_id):
        """
        Return subnet cidrblock in string by lookup with tag_name and vpc ID
        :return: subnet cidrblock
        :param tag_name: a string of subnet tag name
        :param vpc_id: a string of vpc id
        """
        res = self.client.describe_subnets(Filters=[
            {
                'Name': 'tag:Name',
                'Values': [f'{tag_name}']
            },
            {
                'Name': 'vpc-id',
                'Values': [f'{vpc_id}']
            }
        ])
        debug(json.dumps(res, indent=2, default=str))
        assert res['ResponseMetadata']['HTTPStatusCode'] == 200, \
            f'get_subnet_cidrblock_by_tag_name_vpc_id failed due to HTTPStatusCode {
                res["ResponseMetadata"]["HTTPStatusCode"]}'
        return res['Subnets'][0]['CidrBlock']

    def get_route_table_id_by_vpc_id_tag_name(self, vpc_id, tag_name):
        """
        Get route table id via lookup with vpc id and tag_name
        :return: a string of route table matched with vpc id and tag_name
        :param vpc_id: a string of vpc id
        :param tag_name: a string of tag name on target route table
        """
        route_tables = self.client.describe_route_tables(Filters=[
            {'Name': 'vpc-id', 'Values': [f'{vpc_id}']},
            {'Name': 'tag:Name', 'Values': [f'{tag_name}']},
        ])
        assert route_tables['ResponseMetadata'][
            'HTTPStatusCode'] == 200, f'HTTPStatus is not 200 {json.dumps(route_tables, indent=2)}'
        return route_tables['RouteTables'][0]['RouteTableId']

    def check_route_existence_and_delete(self, vpc_id, tag_name, cidr_block):
        """
        Check route entry existence in route table and if so delete it
        :param vpc_id: a string of vpc id holding route table
        :param tag_name: a string of route table tag name
        :param cidr_block: a string of cidr block to check
        """
        route_tables = self.client.describe_route_tables(Filters=[
            {'Name': 'vpc-id', 'Values': [f'{vpc_id}']},
            {'Name': 'tag:Name', 'Values': [f'{tag_name}']},
        ])
        route_table_id = route_tables['RouteTables'][0]['RouteTableId']
        for route in route_tables['RouteTables'][0]['Routes']:
            if route['DestinationCidrBlock'] == cidr_block:
                self.client.delete_route(DestinationCidrBlock=cidr_block,
                                         RouteTableId=route_table_id)

    def check_instance_status(self, instance_id: str) -> dict:
        """
        Check the status checks of an EC2 instance.
        :param instance_id: The ID of the EC2 instance.
        :return: A dictionary containing the status checks results, and current instance state
        """
        info(f"check_instance_status() for {instance_id=}")
        response = self.client.describe_instance_status(
            InstanceIds=[instance_id])
        instance_status = response['InstanceStatuses'][0]
        instance_state = instance_status['InstanceState']['Name']
        system_status = instance_status['SystemStatus']['Status']
        instance_status = instance_status['InstanceStatus']['Status']

        status_checks = {
            'system_status': system_status,
            'instance_status': instance_status,
            'instance_state': instance_state
        }
        info(f"Instance {instance_id} status and state: {status_checks}")
        return status_checks

    def create_tag_for_instance(self, instance_id: str, tag_name: str, tag_value: str) -> dict:
        """
        Adds or overwrites only the specified tags for the specified Amazon EC2 resource or resources. When you specify an existing tag key, the value is overwritten with the new value.

        :param instance_id: The ID of the EC2 instance
        :param tag_name: Name of the Tag
        :param tag_value: Value of the Tag
        :return: A dictionary containing the response from AWS
        """
        info(f"create_tag_for_instance({tag_name=}) for {instance_id=}")
        response = self.client.create_tags(
            Resources=[instance_id],
            Tags=[
                {
                    'Key': tag_name,
                    'Value': tag_value
                }
            ]
        )
        return response

    def stop_instance(self, instance_id: str) -> dict:
        """
        Function to Stop an EC2 instance
        :param instance_id: ID of the EC2 Instance

        :return: Boto3 Response
        """
        info(f"stop_instance({instance_id=})")
        response = self.client.stop_instances(
            InstanceIds=[instance_id]
        )
        return response

    def wait_for_status_and_state(self, instance_id: str, timeout: int = 900) -> bool:
        """
        Wait until an instance passed 2 status_check, and state changed to running
        :param instance_id: The ID of the EC2 instance.
        :param timeout: max time in seconds method will try to get expected result
        :return: True if all 3 requirements meet, else False
        """
        info(f"wait_for_status_and_state() for {instance_id=}")
        status_pass = False
        start_time = time.monotonic()
        time_passed = 0
        impaired = False
        while time_passed < timeout and not status_pass:
            time.sleep(30)
            time_passed = int(time.monotonic() - start_time)
            current_status = self.check_instance_status(instance_id)
            if (current_status.get('system_status', "") == 'ok' and current_status.get('instance_status', "") == 'ok'
                    and current_status.get('instance_state', "") == 'running'):
                status_pass = True
            elif current_status.get('instance_status', "") == 'impaired':
                debug(f"Status of instance {
                      instance_id} showed impaired, try to wait more time to see if it can change to ok")
                impaired = True
        if not status_pass:
            debug(f"The instance {
                  instance_id} did not in running state, or did not pass status_check after {time_passed} secs")
            return False
        if impaired:
            debug(f"Instance {
                  instance_id}'s state changed from impaired to ok finally")
        return True

    def get_all_ec2_instances_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve all EC2 instances for the specified region, optionally filtered by tags.

        This method interacts with the AWS EC2 service using the boto3 client to describe and
        gather details about EC2 instances in the specified region. If tags are provided, only
        instances matching the specified tags will be retrieved. Otherwise, all instances are fetched.

        Args:
            tags (dict[str, str] | None): Optional dictionary of tags to filter EC2 instances.
                Keys are tag names, and values are the tag values to match.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing detailed information
            about an EC2 instance in the specified region.
        """
        info(f"Retrieving EC2 Instances from AWS account {self.account_id} in region: {self.region}{f', with tags {tags}' if tags else ''}")
        instances = []
        if tags:
            filters = [{"Name": f"tag:{key}", "Values": [value]}
                       for key, value in tags.items()]
            response = self.client.describe_instances(Filters=filters)
            debug(f"Ec2 instances with tag {tags}: {response}")
        else:
            response = self.client.describe_instances()
            debug(f"Ec2 instances : {response}")
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances.append(instance)
        return instances

    def get_all_ec2_instances(self, tags: dict[str, str] | None = None) -> list[Ec2Instance]:
        """Convert raw EC2 instance data from AWS to a list of 'Ec2Instance' objects.

        This method retrieves raw EC2 instance data from AWS, processes it, and converts it
        into a list of 'Ec2Instance' data class objects. Optionally, instances can be filtered
        by tags. Each 'Ec2Instance' object includes details such as instance ID, security groups,
        tags, and other metadata.

        Args:
            tags (dict[str, str] | None): Optional dictionary of tags to filter EC2 instances.
                Keys are tag names, and values are the tag values to match.

        Returns:
            list[Ec2Instance]: A list of `Ec2Instance` objects representing EC2 instances
            in the specified region.
        """
        ec2_instance_list = []
        ec2_instances = self.get_all_ec2_instances_raw(tags)

        for instance in ec2_instances:
            # Extract state information
            state_data = instance.get('State', {})
            state = State(
                code=state_data.get('Code', 0),
                name=state_data.get('Name', '')
            )

            # Extract security groups
            security_groups_data = instance.get('SecurityGroups', [])
            security_groups = [
                Ec2SecurityGroup(
                    group_id=sg.get('GroupId', ''),
                    group_name=sg.get('GroupName', '')
                )
                for sg in security_groups_data
            ]

            # Extract tags
            tags_data = instance.get('Tags', [])
            tags = {tag['Key']: tag['Value'] for tag in tags_data}

            # Extract CPU options
            cpu_options_data = instance.get('CpuOptions', {})
            cpu_options = CpuOptions(
                core_count=cpu_options_data.get('CoreCount', 1),
                threads_per_core=cpu_options_data.get('ThreadsPerCore', 1)
            )

            # Extract enclave options
            enclave_options_data = instance.get('EnclaveOptions', {})
            enclave_options = EnclaveOptions(
                enabled=enclave_options_data.get('Enabled', False)
            )

            # Extract hibernation options
            hibernation_options_data = instance.get('HibernationOptions', {})
            hibernation_options = HibernationOptions(
                configured=hibernation_options_data.get('Configured', False)
            )

            # Create an Ec2Instance object
            ec2_instance = Ec2Instance(
                instance_id=instance.get('InstanceId', ''),
                image_id=instance.get('ImageId', ''),
                instance_type=instance.get('InstanceType', ''),
                architecture=instance.get('Architecture', ''),
                hypervisor=instance.get('Hypervisor', ''),
                virtualization_type=instance.get('VirtualizationType', ''),
                state=state,
                private_dns_name=instance.get('PrivateDnsName', ''),
                public_dns_name=instance.get('PublicDnsName', ''),
                launch_time=datetime_to_iso8601(instance.get('LaunchTime', '')),
                subnet_id=instance.get('SubnetId', ''),
                vpc_id=instance.get('VpcId', ''),
                private_ip_address=instance.get('PrivateIpAddress', ''),
                public_ip_address=instance.get('PublicIpAddress'),
                region=self.region,
                account_id=settings.app.aws_account.aws_account_id,
                security_groups=security_groups,
                tags=tags,
                platform_details=instance.get('PlatformDetails', ''),
                usage_operation=instance.get('UsageOperation', ''),
                usage_operation_update_time=datetime_to_iso8601(instance.get('UsageOperationUpdateTime', '')),
                cpu_options=cpu_options,
                ebs_optimized=instance.get('EbsOptimized', False),
                ena_support=instance.get('EnaSupport', False),
                enclave_options=enclave_options,
                hibernation_options=hibernation_options
            )

            ec2_instance_list.append(ec2_instance)
        return ec2_instance_list

    def get_instance_name(self, tags) -> str:
        """Helper function to extract the Name tag from a list of instance's tags."""
        for tag in tags:
            if tag['Key'] == 'Name':
                return tag['Value']
        return ""

    def list_ec2_instances_exposed_to_public(self) -> list:
        """
        List all EC2 instances that with any port open to CIDR 0.0.0.0/0

        :return: A list contains vulnerable EC2 instances info
        """
        security_groups = self.client.describe_security_groups()[
            'SecurityGroups']
        open_sg_ids = set()
        for sg in security_groups:
            for permission in sg.get('IpPermissions', []):
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        open_sg_ids.add(sg['GroupId'])

        instances = self.get_all_ec2_instances_raw()
        vulnerable_instances = []
        for instance in instances:
            for sg in instance['SecurityGroups']:
                if sg['GroupId'] in open_sg_ids:
                    vulnerable_instances.append({
                        'InstanceName': self.get_instance_name(instance['Tags']),
                        'InstanceId': instance['InstanceId'],
                        'PublicIpAddress': instance.get('PublicIpAddress'),
                        'SecurityGroups': [sg['GroupName'] for sg in instance['SecurityGroups']]
                    })

        info(
            f"Instances with any port open to 0.0.0.0/0:"
            f" {json.dumps(vulnerable_instances, indent=2)}"
        )
        return vulnerable_instances

    def list_ec2_instances_exposed_to_public_with_ssh_port_open(self) -> list:
        """
        List all EC2 instances that with port 22 open to CIDR 0.0.0.0/0
        :return: A list contains vulnerable EC2 instances info
        """
        security_groups = self.client.describe_security_groups()['SecurityGroups']
        open_ssh_sg_ids = set()
        for sg in security_groups:
            for permission in sg.get('IpPermissions', []):
                if permission.get('FromPort') == 22 and permission.get('ToPort') == 22:
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            open_ssh_sg_ids.add(sg['GroupId'])

        instances = self.get_all_ec2_instances_raw()
        vulnerable_instances = []
        for instance in instances:
            for sg in instance['SecurityGroups']:
                if sg['GroupId'] in open_ssh_sg_ids:
                    vulnerable_instances.append({
                        'InstanceName': self.get_instance_name(instance['Tags']),
                        'InstanceId': instance['InstanceId'],
                        'PublicIpAddress': instance.get('PublicIpAddress'),
                        'SecurityGroups': [sg['GroupName'] for sg in instance['SecurityGroups']]
                    })

        info(f"Instances with port 22 open to 0.0.0.0/0: {json.dumps(vulnerable_instances, indent=2)}")
        return vulnerable_instances

    def associate_ec2_with_iam_role(self, instance_id: str, iam_role_name: str, iam_role_arn: str) -> str:
        """
        Associate an IAM role to the EC2 instance
        :param instance_id: ID of the EC2 instance
        :param iam_role_name: Name of the IAM role
        :param iam_role_arn: ARN of the IAM role
        :return: Association ID
        """
        response = self.client.associate_iam_instance_profile(
            IamInstanceProfile={
                "Arn": iam_role_arn,
                "Name": iam_role_name
            },
            InstanceId=instance_id
        )
        return response['IamInstanceProfileAssociation']['AssociationId']

    def wait_for_iam_role_attached(self, association_id: str, timeout: int = 300) -> bool:
        """
        Function to wait for an iam association complete
        :param association_id: ID of the IAM Role association
        :param timeout: Max time to wait until the association complete
        """
        info(f"wait_for_iam_role_attached() for {association_id=}")
        start_time = time.monotonic()
        time_passed = 0
        associated = False
        while time_passed < timeout and not associated:
            time.sleep(30)
            time_passed = int(time.monotonic() - start_time)
            current_status = self.client.describe_iam_instance_profile_associations(
                AssociationIds=[association_id]
            )['IamInstanceProfileAssociations'][0]['State']
            if current_status == 'associated':
                associated = True
        if not associated:
            debug(f"The association {association_id} did not in associated state after {time_passed} secs")
            return False
        return True
