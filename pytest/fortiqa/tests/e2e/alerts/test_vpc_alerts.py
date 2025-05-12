import logging
import random
import string
import time
import json
import pytest
import boto3

from datetime import datetime, timedelta
# from fortiqa.libs.lw.apiv1.api_client.alerts.alerts import Alerts
from fortiqa.libs.lw.apiv1.api_client.alerts.alerts import Alert as AlertsV1
from fortiqa.libs.lw.apiv2.api_client.alerts.alerts import Alert as AlertsV2
from fortiqa.libs.lw.apiv2.api_client.policies.policies import Policies as PoliciesV2
from fortiqa.libs.helper.payload_helper import payload_helper
from fortiqa.tests import settings
from botocore.exceptions import ClientError
from playwright.sync_api import sync_playwright
from fortiqa.tests.e2e.alerts.conftest import SLEEP_TIMEOUT, QUERY_TIMEOUT, FILTER_TIME_RANGE

logger = logging.getLogger(__name__)

@pytest.mark.lacework_global_8
def test_root_account(api_v1_client, api_v2_client, aws_account):
    logger.info("""
    ######################################################################################
    ### lacework-global-8   Usage of Root Account
    ######################################################################################""")

    try:
        logger.info(f"***start to generate event***")
        iam = boto3.client(
            'iam',aws_access_key_id=aws_account.aws_root_access_key_id, 
             aws_secret_access_key=aws_account.aws_root_secret_access_key, 
             region_name=aws_account.aws_terraform_s3_backend_region
        )
        start_time_8 = datetime.now()
        alert_trigger_time = time.time()
        response = iam.list_users()
        logger.info(f"***event generated successsfully***")
    except Exception as e:
        logger.error(f"An error occured: {e}")


    # check alert
    # start_time, end_time = calculate_time_range(FILTER_TIME_RANGE,event_time_1)
    minutes = 60
    delta = timedelta(minutes=minutes)
    start_time = start_time_8 - delta    
    start_time = int(start_time.timestamp() * 1000)
    end_time = datetime.now() + delta    
    end_time = int(end_time.timestamp() * 1000)

    start_time_seconds = start_time / 1000.0
    end_time_seconds = end_time / 1000.0
    filter_start_time_dt = datetime.fromtimestamp(start_time_seconds)
    filter_end_time_dt = datetime.fromtimestamp(end_time_seconds)
    logger.info(f"***************************************************************************************")
    logger.info(f"*****Filter alert's start time from: {filter_start_time_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"*****Filter alert's end time until: {filter_end_time_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"***************************************************************************************")

    # Prepare payload for query alerts using api_v1
    '''
    lacework-global-8   Usage of Root Account
    '''

    alert_name_8 = 'Usage of Root Account'

    payload_8 = filter_payload_helper(alert_name_8, start_time, end_time)

    # Query the alert according to filter condition via API v1
    alert_api = AlertsV1(api_v1_client)
    # time.sleep(SLEEP_TIMEOUT)

    resp_8 = alert_api.wait_until_alert_is_generated(payload_8, 30,  900) # 900s = 15min

    alert_gen_time = time.time()
    
    # Assert the queried alert is expected     
    alert_assert(resp_8, alert_name_8, 'Aws', 'CloudTrailCep', 'Critical')
    
    # Teardown, Mark the alert as closed
    # resp = alert_api.close_alert(alert_id=resp_8.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'

    latency = alert_gen_time - alert_trigger_time
    minutes = int(latency % 3600 // 60)
    seconds = int(latency % 60)
    start_dt = datetime.fromtimestamp(alert_trigger_time)
    end_dt = datetime.fromtimestamp(alert_gen_time)
    logger.info(f"******************************************************************************")
    logger.info(f"***** Test completed. *****")
    logger.info(f"***** Latency Time: {minutes} minutes, {seconds:.2f} seconds *****")
    logger.info(f"***** Trigger time: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} to alert generated time: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} . *****")
    logger.info(f"********************************************************************************")


@pytest.mark.vpc
@pytest.mark.lacework_global_2_3_4_5_6_7_28
def test_vpc_1(api_v1_client, api_v2_client, aws_account):
    logger.info("""
    ######################################################################################
    ### lacework-global-2   Security Group Change 
    ### lacework-global-3   Network Access Control List (NACL) Change 
    ### lacework-global-4   Network Gateway Change 
    ### lacework-global-5   Route Table Change 
    ### lacework-global-6   New Virtual Private Network (VPN) Connection 
    ### lacework-global-7   Virtual Private Network (VPN) Gateway Change 
    ### lacework-global-28   New Virtual Private Cloud (VPC) 
    ######################################################################################""")

    # Disable lacework-global-1
    alert_api_v2 = PoliciesV2(api_v2_client)
    resp = alert_api_v2.get_policy_status("lacework-global-1")
    policy_status = resp['data']["enabled"]
    
    if policy_status == True:
        logger.info(f"the policy status is enabled, now change to disabled")
        policy_list = []
        policy_list.append("lacework-global-1")
        modify_policy(api_v1_client, "disabled", policy_list, 3600)
    elif policy_status == False:
        logger.info(f"the policy status is disabled, no action needed")
    else:
        logger.error(f"An error occured on policy_status")

    # resource
    policy_response = None
    now = datetime.now()
    time_sequence = now.strftime("%y-%m-%d-%H-%M-%S")
    ran_str = ''.join(random.choice(string.digits) for i in range(8))

    vpc_name = 'VPC_Name' + "_" + ran_str + time_sequence
    customer_gateway_name = 'customer_gateway_name' + "_" + ran_str + time_sequence
    route_table_name = 'route_table_name' + "_" + ran_str + time_sequence
    network_acl_name = 'network_acl_name' + "_" + ran_str + time_sequence
    security_group_name = 'security_group_name' + "_" + ran_str + time_sequence
    vpn_gateway_name = 'vpn_gateway_name' + "_" + ran_str + time_sequence
    vpn_connection_name = 'vpn_connection_name' + "_" + ran_str + time_sequence

    alert_trigger_time = time.time()

    # generate event
    try:
        logger.info(f"***start to generate event***")
        ec2 = boto3.client(
            'ec2',aws_access_key_id=aws_account.aws_access_key_id, 
             aws_secret_access_key=aws_account.aws_secret_access_key, 
             region_name=aws_account.aws_terraform_s3_backend_region
        )

        # 1. create VPC to trigger lacework-global-28 New Virtual Private Cloud (VPC) 
        start_time_28 = datetime.now()
        policy_response = ec2.create_vpc(
            CidrBlock='10.0.0.0/16',
            TagSpecifications=[{
                'ResourceType': 'vpc',
                'Tags': [{'Key': 'Name', 'Value': vpc_name}]
            }]
        )
        vpc_id = policy_response['Vpc']['VpcId']
        logger.info(f"***VPC created successfully with ID: {vpc_id}***")

        # waiting for vpc avaliable
        time.sleep(5)

        # 2. create Customer Gateway to trigger lacework-global-4 Network Gateway Change 
        start_time_4 = datetime.now()
        customer_gateway_response = ec2.create_customer_gateway(
                BgpAsn=65000,
                PublicIp="8.8.8.8",
                Type="ipsec.1",
                TagSpecifications=[{
                    "ResourceType": "customer-gateway",
                    "Tags": [{"Key": "Name", "Value": customer_gateway_name}]
                }]
        )
        customer_gateway_id = customer_gateway_response["CustomerGateway"]["CustomerGatewayId"]
        logger.info(f"***customer gateway created successfully with ID: {customer_gateway_id}***")

        # 3. create Route Table to trigger lacework-global-5 Route Table Change 
        start_time_5 = datetime.now()
        route_table_response = ec2.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "route-table",
                "Tags": [{"Key": "Name", "Value": route_table_name}]
            }]
        )
        route_table_id = route_table_response["RouteTable"]["RouteTableId"]
        logger.info(f"***route table created successfully with ID: {route_table_id}***")


        # 4. create Network ACL to trigger lacework-global-3 Network Access Control List (NACL) Change 
        start_time_3 = datetime.now()
        network_acl_response = ec2.create_network_acl(
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "network-acl",
                "Tags": [{"Key": "Name", "Value": network_acl_name}]
            }]
        )
        network_acl_id = network_acl_response["NetworkAcl"]["NetworkAclId"]
        logger.info(f"***Network ACL created successfully with ID: {network_acl_id}***")

        # 5. create Security Group to trigger lacework-global-2 Security Group Change 
        start_time_2 = datetime.now()
        security_group_response = ec2.create_security_group(
            GroupName=security_group_name,
            Description="Security group",
            VpcId=vpc_id
        )
        security_group_id = security_group_response["GroupId"]
        logger.info(f"***Security Group created successfully with ID: {security_group_id}***")

        # 6. create VPN Gateway to trigger lacework-global-7 Virtual Private Network (VPN) Gateway Change 
        start_time_7 = datetime.now()
        vpn_gateway_response = ec2.create_vpn_gateway(
            Type="ipsec.1",
            TagSpecifications=[{
                "ResourceType": "vpn-gateway",
                "Tags": [{"Key": "Name", "Value": vpn_gateway_name}]
            }]
        )
        vpn_gateway_id = vpn_gateway_response["VpnGateway"]["VpnGatewayId"]
        logger.info(f"***VPN Gateway created successfully with ID: {vpn_gateway_id}***")

        # 7. create VPN Connection to trigger lacework-global-6 New Virtual Private Network (VPN) Connection 
        vpn_connection_response = None
        vpn_connection_creating_timer = 0
        start_time_6 = datetime.now()
        while (vpn_connection_response == None and vpn_connection_creating_timer < 300 ):
            try:
                start_time_6 = datetime.now()
                vpn_connection_response = ec2.create_vpn_connection(
                    Type="ipsec.1",
                    CustomerGatewayId=customer_gateway_id,
                    VpnGatewayId=vpn_gateway_id,
                    Options={"StaticRoutesOnly": True},
                    TagSpecifications=[{
                        "ResourceType": "vpn-connection",
                        "Tags": [{"Key": "Name", "Value": vpn_connection_name}]
                    }]
                )

            except Exception as e:
                logger.info(f"have been waiting {vpn_connection_creating_timer} seconds, an error occured: {e}")
                time.sleep(5)
                vpn_connection_creating_timer += 5
        
        if vpn_connection_response == None: 
            logger.error(f"have been waiting {vpn_connection_creating_timer} seconds, an error occured: {e}")
        else:
            vpn_connection_id = vpn_connection_response["VpnConnection"]["VpnConnectionId"]
            logger.info(f"***VPN Connection created successfully with ID: {vpn_connection_id}***")
        
        logger.info("***all VPC related event generated ")

    except Exception as e:
        logger.error(f"An error occured: {e}")

    finally:
        if policy_response:
            # teardown
            time.sleep(3)
            logger.info(f"Starting resource deletion...")

            # delete VPN Connection
            ec2.delete_vpn_connection(VpnConnectionId=vpn_connection_id)
            logger.info(f"VPN Connection {vpn_connection_id} deleted.")

            # delete VPN Gateway
            vpn_gateway_deleted = False
            vpn_gateway_deleting_timer = 0
            while (vpn_gateway_deleted == False and vpn_gateway_deleting_timer < 300):
                try:
                    ec2.delete_vpn_gateway(VpnGatewayId=vpn_gateway_id)
                    vpn_gateway_deleted = True
                except Exception as e:
                    logger.info(f"have been waiting {vpn_gateway_deleting_timer} seconds, an error occured: {e}")
                    time.sleep(5)
                    vpn_gateway_deleting_timer += 5
            
            if vpn_gateway_deleted == False: 
                logger.error(f"have been waiting {vpn_connection_creating_timer} seconds, an error occured: {e}")
            else:
                logger.info(f"VPN Gateway {vpn_gateway_id} deleted.")

            # delete Security Group
            ec2.delete_security_group(GroupId=security_group_id)
            logger.info(f"Security Group {security_group_id} deleted.")

            # delete Network ACL
            ec2.delete_network_acl(NetworkAclId=network_acl_id)
            logger.info(f"Network ACL {network_acl_id} deleted.")

            # delete Route Table
            ec2.delete_route_table(RouteTableId=route_table_id)
            logger.info(f"Route Table {route_table_id} deleted.")

            # delete Customer Gateway
            ec2.delete_customer_gateway(CustomerGatewayId=customer_gateway_id)
            logger.info(f"Customer Gateway {customer_gateway_id} deleted.")

            # delete VPC
            ec2.delete_vpc(VpcId=vpc_id)
            logger.info(f"VPC {vpc_id} deleted.")

            logger.info("***All resources deleted successfully!***")

        logger.info("***Teardown down")

    # check alert
    start_time_list = []
    start_time_list.append(start_time_2)
    start_time_list.append(start_time_3)
    start_time_list.append(start_time_4)
    start_time_list.append(start_time_5)
    start_time_list.append(start_time_6)
    start_time_list.append(start_time_7)
    start_time_list.append(start_time_28)

    # start_time, end_time = calculate_time_range(FILTER_TIME_RANGE,cur_base_time)
    minutes = 60
    delta = timedelta(minutes=minutes)
    for i in range(len(start_time_list)):
        start_time_list[i] = start_time_list[i] - delta
        start_time_list[i] = int(start_time_list[i].timestamp() * 1000)

    end_time = datetime.now() + delta    
    end_time = int(end_time.timestamp() * 1000)

    start_time_seconds = start_time_list[-1] / 1000.0
    end_time_seconds = end_time / 1000.0
    filter_start_time_dt = datetime.fromtimestamp(start_time_seconds)
    filter_end_time_dt = datetime.fromtimestamp(end_time_seconds)
    logger.info(f"***************************************************************************************")
    logger.info(f"*****Filter alert's start time from: {filter_start_time_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"*****Filter alert's end time until: {filter_end_time_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"***************************************************************************************")

    # Prepare payload for query alerts using api_v1
    '''
    lacework-global-2   Security Group Change 
    lacework-global-3   Network Access Control List (NACL) Change 
    lacework-global-4   Network Gateway Change 
    lacework-global-5   Route Table Change 
    lacework-global-6   New Virtual Private Network (VPN) Connection 
    lacework-global-7   Virtual Private Network (VPN) Gateway Change 
    lacework-global-28   New Virtual Private Cloud (VPC) 
    '''
    # set alert name
    alert_name_list= []
    alert_name_list.append('Security Group Change')
    alert_name_list.append('Network Access Control List (NACL) Change')
    alert_name_list.append('Network Gateway Change')
    alert_name_list.append('Route Table Change')
    alert_name_list.append('New Virtual Private Network (VPN) Connection')
    alert_name_list.append('Virtual Private Network (VPN) Gateway Change')
    alert_name_list.append('New Virtual Private Cloud (VPC)')

    # set payload
    payload_list= []
    for i in range(len(alert_name_list)):
        payload = filter_payload_helper(alert_name_list[i], start_time_list[i], end_time)
        payload_list.append(payload)

    # Query the alert according to filter condition via API v1
    alert_api = AlertsV1(api_v1_client)
    time.sleep(SLEEP_TIMEOUT)

    # get resp
    resp_list = []
    timeout = 900
    st_time = time.time()
    failed_flag = False
    index = -1

    for payload in payload_list:
        index = index + 1
        try: 
            remaining_timeout = timeout - (time.time() - st_time)
            resp = alert_api.wait_until_alert_is_generated(payload, 15, remaining_timeout)
            resp_list.append(resp)
            
        except TimeoutError as e:
            logger.info(f"***** TimeoutError occured: {e}, alert {alert_name_list[index]} is not genearted")
            failed_flag = True

    if failed_flag == True:
        raise TimeoutError
    
    alert_gen_time = time.time()
    
    # Assert the queried alert is expected     
    for i in range(len(resp_list)):
        alert_assert(resp_list[i], alert_name_list[i], 'Aws', 'CloudTrailCep', 'Medium')

    # Teardown, Mark the alert as closed
    # resp = alert_api.close_alert(alert_id=resp_2.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'
    # resp = alert_api.close_alert(alert_id=resp_3.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'
    # resp = alert_api.close_alert(alert_id=resp_4.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'
    # resp = alert_api.close_alert(alert_id=resp_5.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'
    # resp = alert_api.close_alert(alert_id=resp_6.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'
    # resp = alert_api.close_alert(alert_id=resp_7.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'
    # resp = alert_api.close_alert(alert_id=resp_28.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'

    latency = alert_gen_time - alert_trigger_time
    minutes = int(latency % 3600 // 60)
    seconds = int(latency % 60)
    start_dt = datetime.fromtimestamp(alert_trigger_time)
    end_dt = datetime.fromtimestamp(alert_gen_time)
    logger.info(f"******************************************************************************")
    logger.info(f"***** Test completed. *****")
    logger.info(f"***** Latency Time: {minutes} minutes, {seconds:.2f} seconds *****")
    logger.info(f"***** Trigger time: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} to alert generated time: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} . *****")
    logger.info(f"********************************************************************************")

@pytest.mark.vpc
@pytest.mark.lacework_global_1
def test_vpc_2(api_v1_client, api_v2_client, aws_account):
    logger.info("""
    ######################################################################################
    ### lacework-global-1   Virtual Private Cloud (VPC) Change
    ######################################################################################""")

    # Enable lacework-global-1
    alert_api_v2 = PoliciesV2(api_v2_client)
    resp = alert_api_v2.get_policy_status("lacework-global-1")
    policy_status = resp['data']["enabled"]
    
    if policy_status == True:
        logger.info(f"the policy status is enabled, no action needed")
    elif policy_status == False:
        logger.info(f"the policy status is disabled, now change to enabled")
        policy_list = []
        policy_list.append("lacework-global-1")
        modify_policy(api_v1_client, "enabled", policy_list, 3600)
    else:
        logger.error(f"An error occured on policy_status")

    # resource
    policy_response = None
    now = datetime.now()
    time_sequence = now.strftime("%y-%m-%d-%H-%M-%S")
    ran_str = ''.join(random.choice(string.digits) for i in range(8))
    vpc_name = 'VPC_Name' + "_" + ran_str + time_sequence

    alert_trigger_time = time.time()

    # generate event
    try:
        logger.info(f"***start to generate event***")
        ec2 = boto3.client(
            'ec2',aws_access_key_id=aws_account.aws_access_key_id, 
             aws_secret_access_key=aws_account.aws_secret_access_key, 
             region_name=aws_account.aws_terraform_s3_backend_region
        )

        # create VPC
        start_time_1 = datetime.now()
        policy_response = ec2.create_vpc(
            CidrBlock='10.0.0.0/16',
            TagSpecifications=[{
                'ResourceType': 'vpc',
                'Tags': [{'Key': 'Name', 'Value': vpc_name}]
            }]
        )
        vpc_id = policy_response['Vpc']['VpcId']
        logger.info(f"***VPC created successfully with ID: {vpc_id}***")

        # waiting for vpc avaliable
        time.sleep(5)

    except Exception as e:
        logger.error(f"An error occured: {e}")

    finally:
        if policy_response:
            # teardown
            time.sleep(3)
            logger.info(f"Starting resource deletion...")

            # delete VPC
            ec2.delete_vpc(VpcId=vpc_id)
            logger.info(f"VPC {vpc_id} deleted.")

    # check alert
    # start_time, end_time = calculate_time_range(FILTER_TIME_RANGE,event_time_1)
    minutes = 60
    delta = timedelta(minutes=minutes)
    start_time = start_time_1 - delta    
    start_time = int(start_time.timestamp() * 1000)
    end_time = datetime.now() + delta    
    end_time = int(end_time.timestamp() * 1000)

    start_time_seconds = start_time / 1000.0
    end_time_seconds = end_time / 1000.0
    filter_start_time_dt = datetime.fromtimestamp(start_time_seconds)
    filter_end_time_dt = datetime.fromtimestamp(end_time_seconds)
    logger.info(f"***************************************************************************************")
    logger.info(f"*****Filter alert's start time from: {filter_start_time_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"*****Filter alert's end time until: {filter_end_time_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"***************************************************************************************")

    # Prepare payload for query alerts using api_v1
    '''
    lacework-global-1   Virtual Private Cloud (VPC) Change
    '''

    alert_name_1 = 'Virtual Private Cloud (VPC) Change'

    payload_1 = filter_payload_helper(alert_name_1, start_time, end_time)

    # Query the alert according to filter condition via API v1
    alert_api = AlertsV1(api_v1_client)
    time.sleep(SLEEP_TIMEOUT)

    resp_1 = alert_api.wait_until_alert_is_generated(payload_1, 30,  900) # 900s = 15min

    alert_gen_time = time.time()
    
    # Assert the queried alert is expected     
    alert_assert(resp_1, alert_name_1, 'Aws', 'CloudTrailCep', 'Medium')
    
    # Teardown, Mark the alert as closed
    # resp = alert_api.close_alert(alert_id=resp_1.json()['data'][0]['alertId'])
    # assert resp.json()['message'] == 'SUCCESS'

    latency = alert_gen_time - alert_trigger_time
    minutes = int(latency % 3600 // 60)
    seconds = int(latency % 60)
    start_dt = datetime.fromtimestamp(alert_trigger_time)
    end_dt = datetime.fromtimestamp(alert_gen_time)
    logger.info(f"******************************************************************************")
    logger.info(f"***** Test completed. *****")
    logger.info(f"***** Latency Time: {minutes} minutes, {seconds:.2f} seconds *****")
    logger.info(f"***** Trigger time: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} to alert generated time: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} . *****")
    logger.info(f"********************************************************************************")
