import json
import logging
import time

from datetime import datetime, timedelta
from copy import deepcopy
from typing import Any, Dict
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.api_client.new_agent_dashboard.new_agent_dashboard import NewAgentDashboard
from fortiqa.libs.lw.apiv1.payloads import LaceworkResourceGroupFilter
from fortiqa.libs.lw.apiv1.payloads import AgentFilter

logger = logging.getLogger(__name__)


class AgentsHelper:
    def __init__(self, user_api, agent_deployment_timestamp: datetime = datetime.now()):
        self.user_api = user_api
        start_date = agent_deployment_timestamp - timedelta(hours=7)
        end_date = agent_deployment_timestamp + timedelta(hours=7)
        self.payload_template: Dict[str, Any] = {
            "ParamInfo": {
                "StartTimeRange": int(start_date.timestamp() * 1000.0),
                "EndTimeRange": int(end_date.timestamp() * 1000.0),
                "EnableEvalDetailsMView": True
            },
        }
        self.new_dashboard_payload_template: Dict[str, Any] = {
            "ParamInfo": {
                "StartTimeRange": int(start_date.timestamp() * 1000.0),
                "EndTimeRange": int(end_date.timestamp() * 1000.0),
                "DateRangeOption": "is within",
                "PageSize": 5000,
            },
            "ResourceGroups": LaceworkResourceGroupFilter.all_resource_types(),
            "Filters": {}
        }
        self.filters_by_host_payload = {
            "NavigationKey": {
                "filters": [
                    {
                        "field": "ProcessClusterFilters.{}",
                        "value": "{}",
                        "type": "eq"
                    }
                ]
            }
        }
        self.alert_filter_by_instance_id_payload = {
            "Filters": {
                "ProcessClusterFilters.INSTANCE_ID": [
                    {
                        "filterGroup": "include",
                        "value": ""
                    }
                ]
            }
        }
        self.alert_filter_by_hostname_payload = {
            "Filters": {
                "ProcessClusterFilters.HOSTNAME": [
                    {
                        "filterGroup": "include",
                        "value": ""
                    }
                ]
            }
        }

    def list_all_agents(self) -> list:
        """Helper function to list all agents"""
        logger.info("list_all_agents()")
        payload = deepcopy(self.payload_template)
        payload['OrderBy'] = {
            "field": "CREATED_TIME",
            "order": "Desc"
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card70", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All agents: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_ip_with_no_agent(self) -> list:
        """Helper function to list all IPs with no Lacework agent"""
        logger.info("list_ip_with_no_agent()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card147", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All IPs with no agent: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_all_azure_instance_with_no_agent(self) -> list:
        """Helper function to list all Azure Instances with no Lacework agent"""
        logger.info("list_all_azure_instance_with_no_agent()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="InstancesWithNoAgents_Azure", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All Azure instances with no agent: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_all_gcp_instance_with_no_agent(self) -> list:
        """Helper function to list all GCP Instances with no Lacework agent"""
        logger.info("list_all_gcp_instance_with_no_agent()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="InstancesWithNoAgents_GCP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All GCP instances with no agent: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_all_instances_with_no_agent(self) -> list:
        """Helper function to list all Instances with no Lacework agent"""
        logger.info("list_all_instances_with_no_agent()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="InstancesWithNoAgents", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All instances with no agent: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_all_instances_with_no_agent_or_agentless(self) -> list:
        """Helper function to list all Instances with no Lacework agent or agentless scanning"""
        logger.info("list_all_instances_with_no_agent_or_agentless()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="InstancesWithNoAgentsOrAgentless", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"All instances with no agent or agentless scanning: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_info_by_hostname(self, hostname: str) -> dict | None:
        """
        Helper function to fetch an agent's info by hostname

        :param hostname: Hostname of the agent
        :return: A dictionary contains agent info
        """
        logger.info(f"fetch_agent_info_by_hostname(), {hostname=}")
        all_agent_info = self.list_all_agents()
        for agent_info in all_agent_info:
            if agent_info.get('MACHINE_HOSTNAME', "") == hostname:
                return agent_info
        logger.info(f"Not found agent info for {hostname=}")
        return None

    def fetch_agent_info_by_instance_id(self, instance_id: str) -> dict | None:
        """
        Helper function to fetch an agent's info by instance_id

        :param instance_id: Instance ID of the agent
        :return: A dictionary contains agent info
        """
        logger.info(f"fetch_agent_info_by_instance_id(), {instance_id=}")
        all_agent_info = self.list_all_agents()
        for agent_info in all_agent_info:
            if agent_info.get('TAGS', {}).get('InstanceId') == instance_id:
                return agent_info
        logger.info(f"Not found agent info for {instance_id=}")
        return None

    def fetch_agent_info_by_os(self, os: str) -> list:
        """
        Helper function to fetch an agent's info by OS

        :param os: Agent operating system
        :return: A list contains all agent of the specific os
        """
        logger.info(f"fetch_agent_info_by_os(), {os=}")
        all_agent_info = self.list_all_agents()
        result = []
        for agent_info in all_agent_info:
            if 'AGENT_OS' in agent_info and agent_info['AGENT_OS'].lower() == os.lower():
                result.append(agent_info)
        logger.info(f"Agents with {os=}: {result}")
        return result

    def fetch_agent_info_by_account(self, account: str) -> list:
        """
        Helper function to fetch an agent's info by account

        :param account: Account in which agents were deployed
        :return: A list contains all agent inside the account
        """
        logger.info(f"fetch_agent_info_by_account(), {account=}")
        all_agent_info = self.list_all_agents()
        result = []
        for agent_info in all_agent_info:
            if agent_info.get('TAGS', {}).get('Account') == account:
                result.append(agent_info)
        logger.info(f"Agents in {account=}: {result}")
        return result

    def fetch_agent_external_in_Bytes(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's External In Bytes by account

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_in_Bytes(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card158_DataCenterProcess_ExternalInKBytes", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"ExternalInKBytes: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_server_connections(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's External Server connections by account

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_server_connections(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card158_DataCenterProcess_ExternalServerConnections", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"ExternalServerConnections: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_client_connections(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's External Client connections by account

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_client_connections(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card158_DataCenterProcess_ExternalClientConnections", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"ExternalClientConnections: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_alerts(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's External Client connections by account

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_alerts(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        if filter_type == "HOSTNAME":
            filter = deepcopy(self.alert_filter_by_hostname_payload)
        elif filter_type == "INSTANCE_ID":
            filter = deepcopy(self.alert_filter_by_instance_id_payload)
        filter['Filters'][f"ProcessClusterFilters.{filter_type}"][0]["value"] = instance_id or hostname
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card113_AlertInbox", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Alerts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_out_bytes(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's External Out Bytes

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_out_bytes(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card158_DataCenterProcess_ExternalOutKBytes", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"ExternalOutBytes: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_unique_user(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's number of unique users

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_unique_user(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card179_User", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Users: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_unique_machine(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's number of unique machines

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_unique_user(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card179_Machine", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique Machines: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_total_connections(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's number of total connections

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_total_connections(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card158_DataCenterProcess_TotalConnections", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Total connections: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_total_bytes(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's total bytes

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_total_connections(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card158_DataCenterProcess_TotalKBytes", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Total bytes: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_server_connection_details_udp(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's external UDP server connection details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_server_connection_details_udp(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card80_UDP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"UDP connections details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_server_connection_details_tcp(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's external TCP server connection details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_server_connection_details_tcp(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card80_TCP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"TCP connections details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_dropped_packets_summary(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's external dropped packets summary

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_dropped_packets_summary(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card156", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Dropped packet summary: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_list_of_active_executables(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's active executables

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_list_of_active_executables(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card187", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Active executables: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_executable_info(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's executables' info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_executable_info(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card189", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Executables info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_active_containers(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's active containers

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_active_containers(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card197", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Active containers: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_container_info(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's containers' info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_container_info(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card199", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Containers info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_machine_properties(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's machine properties

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_machine_properties(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card34", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Machine properties: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_machine_tag_summary(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's machine tag summary

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_machine_tag_summary(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card190", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Machine tag summary: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_exposed_ports(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's exposed ports

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_exposed_ports(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card30", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Exposed ports: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_user_login_activity(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's user login activity

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_user_login_activity(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card25", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"User login activity: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_user_authentication_summary(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's user authentication summary

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_user_authentication_summary(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card36", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"User authentication summary: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_bad_login_summary(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's bad login summary summary

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_bad_login_summary(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card162", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Bad login summary: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_client_connection_detail_tcp(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's external TCP client connection details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_client_connection_detail_tcp(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card32_TCP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"External TCP Client connection details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_external_client_connection_detail_udp(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's external UDP client connection details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_external_client_connection_detail_udp(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card32_UDP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"External UDP Client connection details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_internal_client_connection_detail_tcp(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's internal TCP client connection details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_internal_client_connection_detail_tcp(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card33_TCP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Internal TCP Client connection details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_internal_client_connection_detail_udp(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's internal UDP client connection details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_internal_client_connection_detail_udp(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card33_UDP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Internal UDP Client connection details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_hostname_to_instance_id(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's instance_id mapping

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_hostname_to_instance_id(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card34_HostnameToInstanceId", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Instance ID mapping details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_interfaces(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's interfaces

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_hostname_interfaces(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card161", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Interfaces on a machine: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_domain_lookups(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's domain lookups info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_domain_lookups(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card63", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Domain lookups info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_unique_process_details(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's unique process details

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_unique_process_details(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card40", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"Unique process details info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_tcp_internal_connection_from_internal_devices_without_agents(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's TCP internal connection from internal devices without agents info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_tcp_internal_connection_from_internal_devices_without_agents(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card33_FromInternalDevice_TCP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"TCP internal connection from internal devices without agents info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_udp_internal_connection_from_internal_devices_without_agents(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's UDP internal connection from internal devices without agents info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_udp_internal_connection_from_internal_devices_without_agents(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card33_FromInternalDevice_UDP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"UDP internal connection from internal devices without agents info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_tcp_internal_connection_to_internal_devices_without_agents(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's TCP internal connection to internal devices without agents info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_tcp_internal_connection_to_internal_devices_without_agents(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card33_ToInternalDevice_TCP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"TCP internal connection to internal devices without agents info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_udp_internal_connection_to_internal_devices_without_agents(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's UDP internal connection to internal devices without agents info

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_udp_internal_connection_to_internal_devices_without_agents(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Card33_ToInternalDevice_UDP", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"UDP internal connection to internal devices without agents info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_agent_list_of_detected_secrets(self, filter_type: str, instance_id: str = "", hostname: str = "") -> dict:
        """
        Helper function to fetch an agent's list of detected secrets

        :param filter_type: HOSTNAME or INSTANCE_ID
        :param instance_id: Instance ID of the host, required if filter = INSTANCE_ID
        :param hostname: Hostname, required if filter = HOSTNAME
        :return: Query Card response
        """
        logger.info(f"fetch_agent_list_of_detected_secrets(), filter by: {filter_type}={instance_id or hostname}")
        payload = deepcopy(self.payload_template)
        filter = deepcopy(self.filters_by_host_payload)
        filter["NavigationKey"]["filters"][0]["field"] = filter["NavigationKey"]["filters"][0]["field"].format(filter_type)
        filter["NavigationKey"]["filters"][0]["value"] = filter["NavigationKey"]["filters"][0]["value"].format(instance_id or hostname)
        payload.update(filter)  # type: ignore[arg-type]
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="AgentlessDataSecretsHostSummary", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.info(f"List of detected secrets info: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def wait_until_agent_is_added(self, instance_id, wait_until: int):
        """Waits for agent to be added for up to 20 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent to be added to Lacework.

        Returns: None
        Raises: TimeoutError if agent is not added in 20 minutes
        """
        all_agents = []
        agent_found = False
        first_try = True
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and not agent_found):
            if not first_try:
                time.sleep(120)
            first_try = False
            all_agents = self.list_all_agents()
            for agent in all_agents:
                if agent.get('TAGS', {}).get('InstanceId') == instance_id:
                    agent_found = True
                    time_passed = int(time.monotonic() - start_time)
                    logger.info(f"Host {instance_id} is added to Agent dashboard after {time_passed} secs")
                    break
        if not agent_found:
            raise TimeoutError(
                f'Agent {instance_id} was not returned by API'
                f'Last list of agents: {all_agents}'
            )

    def wait_until_agent_is_active(self, instance_id, wait_until: int):
        """Waits for agent to become active for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent to become active.

        Returns: None
        Raises: TimeoutError if agent is not active in 120 minutes
        """
        all_agents = []
        agent_status = None
        first_try = True
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and agent_status != 'ACTIVE'):
            if not first_try:
                time.sleep(240)
            first_try = False
            all_agents = self.list_all_agents()
            for agent in all_agents:
                if agent.get('TAGS', {}).get('InstanceId') == instance_id:
                    agent_status = agent['STATUS']
                    break
        if agent_status != 'ACTIVE':
            raise TimeoutError(
                f'Agent {instance_id} did not become active.'
                f'Last status: {agent_status}'
            )
        time_passed = int(time.monotonic() - start_time)
        logger.info(f"Host {instance_id} is active in the Agent dashboard after {time_passed} secs")

    def wait_until_agent_dashboard_has_unique_machines(self, instance_id, wait_until: int):
        """Waits for agent's unique machine to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's unique machine to become available.

        Returns: None
        Raises: TimeoutError if agent's unique machines board is not available in 120 minutes
        """
        unique_machines = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not unique_machines):
            if not first_try:
                time.sleep(240)
            first_try = False
            agent_unique_machine_data = self.fetch_agent_unique_machine(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in agent_unique_machine_data:
                if data['COUNT']:
                    unique_machines = data['COUNT']
        if unique_machines is None:
            raise TimeoutError(
                f'Agent {instance_id} unique machines board is not ready.'
                f'Last data: {unique_machines}'
            )

    def wait_until_agent_dashboard_has_unique_users(self, instance_id, wait_until: int):
        """Waits for agent's unique users to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's unique users to become available.

        Returns: None
        Raises: TimeoutError if agent's unique users board is not available in 120 minutes
        """
        unique_users = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not unique_users):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_unique_user(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    unique_users = data['COUNT']
        if unique_users is None:
            raise TimeoutError(
                f'Agent {instance_id} unique users board is not ready.'
                f'Last data: {unique_users}'
            )

    def wait_until_agent_dashboard_has_total_bytes(self, instance_id, wait_until: int):
        """Waits for agent's total bytes board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's total bytes board to become available.

        Returns: None
        Raises: TimeoutError if agent's total bytes board is not available in 120 minutes
        """
        total_bytes = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not total_bytes):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_total_bytes(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    total_bytes = data['COUNT']
        if total_bytes is None:
            raise TimeoutError(
                f'Agent {instance_id} unique total bytes board is not ready.'
                f'Last data: {total_bytes}'
            )

    def wait_until_agent_dashboard_has_total_connections(self, instance_id, wait_until: int):
        """Waits for agent's total connections board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's total connections board to become available.

        Returns: None
        Raises: TimeoutError if agent's total connections board is not available in 120 minutes
        """
        total_connections = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not total_connections):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_total_connections(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    total_connections = data['COUNT']
        if total_connections is None:
            raise TimeoutError(
                f'Agent {instance_id} unique total connections board is not ready.'
                f'Last data: {total_connections}'
            )

    def wait_until_agent_dashboard_has_external_out_bytes(self, instance_id, wait_until: int):
        """Waits for agent's external out bytes board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's external out bytes board to become available.

        Returns: None
        Raises: TimeoutError if agent's external out bytes board is not available in 120 minutes
        """
        external_out_bytes = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not external_out_bytes):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_external_out_bytes(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    external_out_bytes = data['COUNT']
        if external_out_bytes is None:
            raise TimeoutError(
                f'Agent {instance_id} unique external out bytes board is not ready.'
                f'Last data: {external_out_bytes}'
            )

    def wait_until_agent_dashboard_has_external_in_bytes(self, instance_id, wait_until: int):
        """Waits for agent's external in bytes board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's external in bytes board to become available.

        Returns: None
        Raises: TimeoutError if agent's external in bytes board is not available in 120 minutes
        """
        external_in_bytes = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not external_in_bytes):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_external_in_Bytes(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    external_in_bytes = data['COUNT']
        if external_in_bytes is None:
            raise TimeoutError(
                f'Agent {instance_id} external in bytes board is not ready.'
                f'Last data: {external_in_bytes}'
            )

    def wait_until_agent_dashboard_has_external_in_connections(self, instance_id, wait_until: int):
        """Waits for agent's external in connections board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's external in connections board to become available.

        Returns: None
        Raises: TimeoutError if agent's external in connections board is not available in 120 minutes
        """
        external_in_connections = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not external_in_connections):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_external_client_connections(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    external_in_connections = data['COUNT']
        if external_in_connections is None:
            raise TimeoutError(
                f'Agent {instance_id} external in connections board is not ready.'
                f'Last data: {external_in_connections}'
            )

    def wait_until_agent_dashboard_has_external_out_connections(self, instance_id, wait_until: int):
        """Waits for agent's external out connections board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's external out connections board to become available.

        Returns: None
        Raises: TimeoutError if agent's external out connections board is not available in 120 minutes
        """
        external_out_connections = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and not external_out_connections):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_external_server_connections(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['COUNT']:
                    external_out_connections = data['COUNT']
        if external_out_connections is None:
            raise TimeoutError(
                f'Agent {instance_id} external out connections board is not ready.'
                f'Last data: {external_out_connections}'
            )

    def wait_until_agent_dashboard_has_instance_id_mapping(self, instance_id, wait_until: int):
        """Waits for agent's external out connections board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's external out connections board to become available.

        Returns: None
        Raises: TimeoutError if agent's external out connections board is not available in 120 minutes
        """
        instance_id_mapping = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not instance_id_mapping):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_hostname_to_instance_id(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                assert data['INSTANCE_ID'] == instance_id, f"Expected to find instance id: {instance_id}, but found {data}"
                instance_id_mapping = True
        if not instance_id_mapping:
            raise TimeoutError(
                f'Agent {instance_id} external out connections board is not ready.'
                f'Last data: {data}'
            )

    def wait_until_agent_dashboard_has_tcp_external_server_connection_details(self, instance_id, wait_until: int):
        """Waits for agent's tcp external server connection details board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's tcp external server connection details board to become available.

        Returns: None
        Raises: TimeoutError if agent's tcp external server connection details board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_external_server_connection_details_tcp(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} tcp external server connection details board is not ready.'
            )

    def wait_until_agent_dashboard_has_list_of_active_executables(self, instance_id, wait_until: int):
        """Waits for agent's list of active executables board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's list of active executables board to become available.

        Returns: None
        Raises: TimeoutError if agent's list of active executables board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_list_of_active_executables(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} list of active executables board is not ready.'
            )

    def wait_until_agent_dashboard_has_list_of_active_containers(self, instance_id, wait_until: int):
        """Waits for agent's list of active containers to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's list of active containers become available.

        Returns: None
        Raises: TimeoutError if agent's list of active containers is not available in a given time.
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_active_containers(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} list of active containers is not ready.'
            )

    def wait_until_agent_dashboard_has_executable_info(self, instance_id, wait_until: int):
        """Waits for agent's executable information board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's executable information board to become available.

        Returns: None
        Raises: TimeoutError if agent's executable information board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_executable_info(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} executable information board is not ready.'
            )

    def wait_until_agent_dashboard_has_machine_properties(self, instance_id, wait_until: int):
        """Waits for agent's machine properties board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's machine properties board to become available.

        Returns: None
        Raises: TimeoutError if agent's machine properties board is not available in 120 minutes
        """
        machine_properties = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not machine_properties):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_machine_properties(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                assert data['TAGS']['InstanceId'] == instance_id, f"Expected to find instance id: {instance_id}, but found {data}"
                machine_properties = True
        if not machine_properties:
            raise TimeoutError(
                f'Agent {instance_id} machine properties board is not ready.'
                f'Last data: {data}'
            )

    def wait_until_agent_dashboard_has_machine_tag_summary(self, instance_id, wait_until: int):
        """Waits for agent's machine tag summary board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's machine tag summary board to become available.

        Returns: None
        Raises: TimeoutError if agent's machine tag summary board is not available in 120 minutes
        """
        machine_tag_summary = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not machine_tag_summary):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_machine_tag_summary(filter_type="INSTANCE_ID", instance_id=instance_id)
            for data in data_returned:
                if data['TAG'] == 'InstanceId':
                    assert data['VALUE'] == instance_id, f"Expected to find instance id: {instance_id}, but found {data}"
                    machine_tag_summary = True
                    break
        if not machine_tag_summary:
            raise TimeoutError(
                f'Agent {instance_id} machine tag summary board is not ready.'
                f'Last data: {data}'
            )

    def wait_until_agent_dashboard_has_interfaces_on_a_machine(self, instance_id, wait_until: int):
        """Waits for agent's interfaces on a machine board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's interfaces on a machine board to become available.

        Returns: None
        Raises: TimeoutError if agent's interfaces on a machine board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_interfaces(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} interfaces on a machine board is not ready.'
            )

    def wait_until_agent_dashboard_has_exposed_ports(self, instance_id, wait_until: int):
        """Waits for agent's exposed ports board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's exposed ports board to become available.

        Returns: None
        Raises: TimeoutError if agent's exposed ports board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_exposed_ports(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} exposed ports board is not ready.'
            )

    def wait_until_agent_dashboard_has_udp_external_client_connection_details(self, instance_id, wait_until: int):
        """Waits for agent's UDP external client connection details board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's UDP external client connection details board to become available.

        Returns: None
        Raises: TimeoutError if agent's UDP external client connection details board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_external_client_connection_detail_udp(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} UDP external client connection details board is not ready.'
            )

    def wait_until_agent_dashboard_has_domain_lookups(self, instance_id, wait_until: int):
        """Waits for agent's domain lookups board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's domain lookups board to become available.

        Returns: None
        Raises: TimeoutError if agent's domain lookups board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_domain_lookups(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} domain lookups board is not ready.'
            )

    def wait_until_agent_dashboard_has_unique_process_details(self, instance_id, wait_until: int):
        """Waits for agent's unique process details board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's unique process details board to become available.

        Returns: None
        Raises: TimeoutError if agent's unique process details board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_unique_process_details(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} unique process details board is not ready.'
            )

    def wait_until_agent_dashboard_has_tcp_internal_connection_to_internal_devices_without_agents(self, instance_id, wait_until: int):
        """Waits for agent's TCP-Internal Connection to Internal Devices without Agents board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's TCP-Internal Connection to Internal Devices without Agents board to become available.

        Returns: None
        Raises: TimeoutError if agent's TCP-Internal Connection to Internal Devices without Agents board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_tcp_internal_connection_to_internal_devices_without_agents(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} TCP-Internal Connection to Internal Devices without Agents board is not ready.'
            )

    def wait_until_agent_dashboard_has_tcp_internal_connection_from_internal_devices_without_agents(self, instance_id, wait_until: int):
        """Waits for agent's TCP-Internal Connection from Internal Devices without Agents board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's TCP-Internal Connection from Internal Devices without Agents board to become available.

        Returns: None
        Raises: TimeoutError if agent's TCP-Internal Connection from Internal Devices without Agents board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_tcp_internal_connection_from_internal_devices_without_agents(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} TCP-Internal Connection from Internal Devices without Agents board is not ready.'
            )

    def wait_until_agent_dashboard_has_udp_internal_connection_to_internal_devices_without_agents(self, instance_id, wait_until: int):
        """Waits for agent's UDP-Internal Connection to Internal Devices without Agents board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's UDP-Internal Connection to Internal Devices without Agents board to become available.

        Returns: None
        Raises: TimeoutError if agent's UDP-Internal Connection to Internal Devices without Agents board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_udp_internal_connection_to_internal_devices_without_agents(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} UDP-Internal Connection to Internal Devices without Agents board is not ready.'
            )

    def wait_until_agent_dashboard_has_udp_internal_connection_from_internal_devices_without_agents(self, instance_id, wait_until: int):
        """Waits for agent's UDP-Internal Connection to Internal Devices without Agents board from become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's UDP-Internal Connection from Internal Devices without Agents board to become available.

        Returns: None
        Raises: TimeoutError if agent's UDP-Internal Connection from Internal Devices without Agents board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_udp_internal_connection_from_internal_devices_without_agents(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} UDP-Internal Connection from Internal Devices without Agents board is not ready.'
            )

    def wait_until_agent_dashboard_has_alerts(self, instance_id, wait_until: int):
        """Waits for agent's alerts board to become available for up to 120 minutes.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent's alerts board to become available.

        Returns: None
        Raises: TimeoutError if agent's alerts board is not available in 120 minutes
        """
        found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not found):
            if not first_try:
                time.sleep(240)
            first_try = False
            data_returned = self.fetch_agent_alerts(filter_type="INSTANCE_ID", instance_id=instance_id)
            if data_returned:
                found = True
        if not found:
            raise TimeoutError(
                f'Agent {instance_id} alerts board is not ready.'
            )

    def list_all_agents_in_new_dashboard(self) -> list:
        """Helper function to list all agents inside new agent dashboard"""
        logger.info("list_all_agents_in_new_dashboard()")
        payload = deepcopy(self.new_dashboard_payload_template)
        payload['OrderBy'] = {
            "field": "FIRST_SEEN",
            "order": "Desc"
        }
        agent_inventory_table_response = NewAgentDashboard(self.user_api).get_agent_inventory(payload=payload)
        assert agent_inventory_table_response.status_code == 200, f"Failed to get agent inventory inside new agent dashboard, error: {agent_inventory_table_response.text}"
        logger.info(f"All agents inside agent inventory table: {json.dumps(agent_inventory_table_response.json(), indent=2)}")
        return agent_inventory_table_response.json()['data']

    def wait_until_agent_is_added_to_new_dashboard(self, instance_id, wait_until: int):
        """Waits for agent to be added to the new agent dashboard given a timestamp.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent to be added to the new agent dashboard in Lacework.

        Returns: None
        Raises: TimeoutError if agent is not added in 20 minutes
        """
        all_agents = []
        agent_found = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not agent_found):
            if not first_try:
                time.sleep(120)
            first_try = False
            all_agents = self.list_all_agents_in_new_dashboard()
            for agent in all_agents:
                if agent.get('MACHINE_TAGS', {}).get('InstanceId') == instance_id:
                    agent_found = True
        if not agent_found:
            raise TimeoutError(
                f'Agent {instance_id} was not returned by API'
                f'Last list of agents: {all_agents}'
            )

    def wait_until_agent_is_active_in_new_agent_dashboard(self, instance_id, wait_until: int):
        """Waits for agent to become active for up to the given timestamp in the new agent dashboard.

        Args:
            instance_id: AWS isntance ID
            wait_until: Unix time until we wait for agent to become active.

        Returns: None
        Raises: TimeoutError if agent is not active in 120 minutes
        """
        all_agents = []
        agent_status = None
        first_try = True
        while first_try or (time.monotonic() < wait_until and agent_status != 'ACTIVE'):
            if not first_try:
                time.sleep(240)
            first_try = False
            all_agents = self.list_all_agents_in_new_dashboard()
            for agent in all_agents:
                if agent.get('MACHINE_TAGS', {}).get('InstanceId') == instance_id:
                    agent_status = agent['STATUS']
        if agent_status != 'ACTIVE':
            raise TimeoutError(
                f'Agent {instance_id} did not become active.'
                f'Last status: {agent_status}'
            )

    def fetch_agent_info_by_hostname_in_new_dashboard(self, hostname: str) -> list:
        """
        Fetch agent detail information by hostname

        Args:
            hostname: Hostname of the host

        Returns: List of detail information collected by the agent installed
        Raises: Exception if not found the host
        """
        logger.info(f'fetch_agent_info_by_hostname_in_new_dashboard({hostname=})')
        payload = deepcopy(self.new_dashboard_payload_template)
        payload['Filters'][AgentFilter.HOSTNAME] = [{
            "value": hostname,
            "filterGroup": "include"
        }]
        response = NewAgentDashboard(self.user_api).get_agent_inventory(payload=payload)
        assert response.status_code == 200, f"Failed to get agent inventory inside new agent dashboard, error: {response.text}"
        if response.json()['data']:
            return response.json()['data']
        else:
            raise Exception(f"Fail to find host with {hostname=}")

    def fetch_agent_info_by_instance_id_in_new_dashboard(self, instance_id: str) -> list:
        """
        Fetch agent detail information by instance_id

        Args:
            instance_id: Instance Id of the host

        Returns: List of detail information collected by the agent installed
        Raises: Exception if not found the host
        """
        logger.info(f'fetch_agent_info_by_instance_id_in_new_dashboard({instance_id=})')
        payload = deepcopy(self.new_dashboard_payload_template)
        payload['Filters'][AgentFilter.INSTANCE_ID] = [{
            "value": instance_id,
            "filterGroup": "include"
        }]
        response = NewAgentDashboard(self.user_api).get_agent_inventory(payload=payload)
        assert response.status_code == 200, f"Failed to get agent inventory inside new agent dashboard, error: {response.text}"
        if response.json()['data']:
            return response.json()['data']
        else:
            raise Exception(f"Fail to find host with {instance_id=}")

    def fetch_host_MID_by_instance_id(self, instance_id: str) -> str:
        """
        Fetch agent's MID from new Agent dashboard by instance_id

        Args:
            instance_id: Instance Id of the host

        Returns: Agent's MID
        Raises: Exception if not found the host, or the MID field is missing
        """
        logger.info(f'fetch_host_MID_by_instance_id({instance_id=})')
        agent_info = self.fetch_agent_info_by_instance_id_in_new_dashboard(instance_id)[0]
        if "MID" in agent_info:
            return agent_info['MID']
        raise Exception(f"Fail to find MID for host with {instance_id=}")

    def fetch_host_MID_by_hostname(self, hostname: str) -> str:
        """
        Fetch agent's MID from new Agent dashboard by hostname

        Args:
            hostname: Hostname

        Returns: Agent's MID
        Raises: Exception if not found the host, or the MID field is missing
        """
        logger.info(f'fetch_host_MID_by_hostname({hostname=})')
        agent_info = self.fetch_agent_info_by_hostname_in_new_dashboard(hostname)[0]
        if "MID" in agent_info:
            return agent_info['MID']
        raise Exception(f"Fail to find MID for host with {hostname=}")
