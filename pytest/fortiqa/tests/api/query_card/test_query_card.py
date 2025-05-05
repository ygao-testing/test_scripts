import logging
import pytest

from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


HOST_VULN_QUERY_CARDS = [
    "ResourceExplorer_FilterValues_Account",  # Filter values for Resource Explorer based on account
    "Card190",  # List all tags inside Host vulnerabilities
    "HostVuln_StatsSummaryAll",  # Summary of all host vulnerabilities
    "HostVuln_ScanStatus",  # Summary of Host vulnerabilities scanning status
    "HostVuln_StatsSummaryCVETrend",  # Trends in CVE vulnerabilities for hosts
    "HostVuln_HostCoverageType",  # List coverage type inside host vulnerabilities
    "HostVuln_HostsSummaryAll_MV_NamedSet",  # Named set summary of all host vulnerabilities
]

CONTAINER_VULN_QUERY_CARDS = [
    "Vuln_PodNamespaceView",  # List all Pod namespaces
    "Vuln_K8sClusterView",  # List all K8S cluster
    "Vuln_StatsSummaryAll_MV",  # Summary of all Container vulnerabilities stats
    "Vuln_StatsSummaryCVETrend_MV",  # Summary of Container vulnerabilities CVE trend
    "Vuln_RecentEvalSummaryWithActiveContainer_MV",  # Recent eval summary with active container
]

AGENT_QUERY_CARDS = [
    "Card236",  # List all agent upgrades
    "Card70",  # List all agents
    "InstancesWithNoAgents",  # List of instances without agents installed
    "InstancesWithNoAgentsOrAgentless",  # Instances lacking both agents or agentless scanning
    "InstancesWithNoAgents_Azure",  # Azure instances without agents
    "InstancesWithNoAgents_GCP",  # GCP instances without agents
    "Card147",  # List IPs with no agent
    "Card158_DataCenterProcess_ExternalInKBytes",  # Agent ExternalInBytes
    "Card158_DataCenterProcess_ExternalServerConnections",  # Agent ExternalServerConnection
    "Card158_DataCenterProcess_ExternalClientConnections",  # Agent ExternalClientConnection
    "Card113_AlertInbox",  # Agent ExternalServerConnectionsss
    "Card158_DataCenterProcess_ExternalOutKBytes",  # Agent ExternalOutBytes
    "Card179_User",  # Agent Unique User
    "Card179_Machine",  # Agent Unique Machine
    "Card158_DataCenterProcess_TotalConnections",  # Agent Total connections
    "Card158_DataCenterProcess_TotalKBytes",  # Agent Total Bytes
    "Card80_UDP",  # Agent external UDP server connection details
    "Card80_TCP",  # Agent external TCP server connection details
    "Card156",  # Agent external dropped packets summary
    "Card187",  # Agent active executables
    "Card189",  # Agent executables' info
    "Card197",  # Agent active containers
    "Card199",  # Agent Container info
    "Card34",  # Agent Machine properties
    "Card190",  # Agent machine tag summary
    "Card30",  # Agent open ports
    "Card25",  # Agent User login activity
    "Card36",  # Agent user authentication summary
    "Card162",  # Agent bad login summary summary
    "Card32_TCP",  # Agent external TCP client connection details
    "Card32_UDP",  # Agent external UDP client connection details
    "Card33_TCP",  # Agent internal TCP client connection details
    "Card33_UDP",  # Agent internal UDP client connection details
    "Card34_HostnameToInstanceId",  # Agent instance_id mapping
    "Card161",  # Agent interface
    "Card63",  # Agent domain lookups info
    "Card40",  # Agent unique process details
    "Card33_FromInternalDevice_TCP",  # Agent TCP internal connection from internal devices without agents info
    "Card33_FromInternalDevice_UDP",  # Agent UDP internal connection from internal devices without agents info
    "Card33_ToInternalDevice_TCP",  # Agent TCP internal connection to internal devices without agents info
    "Card33_ToInternalDevice_UDP",  # Agent UDP internal connection to internal devices without agents info
    "AGENT_FLEET_InventoryTable",  # New Agent Dashboard
]

AGENTLESS_QUERY_CARDS = [
    "Agentless_CLOUD_ACCOUNTS_INVENTORY",  # List all cloud accounts with agentless
    "Agentless_RESOURCE_INVENTORY",  # List all resources scanned agentless
    "AgentlessDataSecretsHostSummary",  # List all detected secrets
]

CLOUDTRAIL_LOG_QUERY_CARDS = [
    "CloudTrailAccountsList",  # List all cloud accounts with cloudtrail onboarded
    "CloudTrailRawEventTS",  # CloudTrail events data
    "CloudTrailUserTS",  # CloudTrail users data
    "CloudTrailDistinctAccountTS",  # CloudTrail unique accounts data
    "CloudTrailDistinctServiceTS",  # CloudTrail unique service data
    "CloudTrailAlertTS",  # CloudTrail unique alerts data
    "CloudTrailDistinctApiTS",  # CloudTrail unique API data
    "CloudTrailDistinctRegionTS",  # CloudTrail unique region data
    "CloudTrailDistinctErrorTS",  # CloudTrail unique error data
    "Card113_AlertInbox",  # CloudTrail alert data
    "Card237",  # CloudTrail logs
    "Card245",  # CloudTrail User details collected
    "Card241",  # CloudTrail User events collected
    "Card246",  # CloudTrail API Error Events collected
]

current_time = datetime.now()
seven_days_ago = current_time - timedelta(days=7)
tomorrow = current_time + timedelta(days=1)
minimal_payload = {
    "ParamInfo": {
        "StartTimeRange": int(seven_days_ago.timestamp()),
        "EndTimeRange": int(tomorrow.timestamp()),
    }
}
attack_path_paraminfo = {
    "StartTimeRange": int(seven_days_ago.timestamp()),
    "EndTimeRange": int(tomorrow.timestamp()),
    "RESOURCE_ID": "",
    "RESOURCE_NAME": "",
    "EVAL_GUID": "",
    "CLOUD_PROVIDER": "",
}
azure_attack_path_payload = {"ParamInfo": dict(attack_path_paraminfo, CLOUD_PROVIDER="Azure")}
aws_attack_path_payload = {"ParamInfo": dict(attack_path_paraminfo, CLOUD_PROVIDER="AWS")}
gcp_attack_path_payload = {"ParamInfo": dict(attack_path_paraminfo, CLOUD_PROVIDER="GCP")}


def _map_payload(payload: dict, query_cards: list) -> list[tuple]:
    return list(map(
        lambda x: (x, payload),
        query_cards))


@pytest.mark.qa_pre_merge
@pytest.mark.parametrize(
    "query_card,payload",
    _map_payload(
        minimal_payload,
        HOST_VULN_QUERY_CARDS + CONTAINER_VULN_QUERY_CARDS + AGENT_QUERY_CARDS + AGENTLESS_QUERY_CARDS + CLOUDTRAIL_LOG_QUERY_CARDS)
    + [
        ("AWS_ComplianceInfoPerResource_EvalGuid", aws_attack_path_payload),
        ("Azure_ComplianceInfoPerResource_EvalGuid", azure_attack_path_payload),
        ("GCP_ComplianceInfoPerResource_EvalGuid", gcp_attack_path_payload),
    ]
)
def test_card(api_v1_client, query_card, payload):
    """Test case for specific query cards

    Given: A list of query cards that are pre-defined
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        query_card: Query card to be tested
    """
    logger.info(f"Test execution of Query Card: {query_card}")
    query_card_api = QueryCard(api_v1_client)
    query_response = query_card_api.exec_query_card(card_name=query_card, payload=payload)
    assert query_response.status_code == 200, f"Fail to execute {query_card}, err: {query_response.text}"
