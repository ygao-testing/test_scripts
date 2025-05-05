import logging
import pytest

from fortiqa.libs.lw.apiv1.api_client.new_vuln.payloads import NewVulnDataclass, QueryEntity, ComparisonOperator
from fortiqa.tests.api.new_vulnerabilities.conftest import generate_new_vuln_payload_and_query

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


@pytest.mark.parametrize("vuln_id", [
    "CVE-2001-1454",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.STARTS_WITH

])
def test_show_host_vulnerability_id(api_v1_client, vuln_id, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability->Vuln Id

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability->Vuln Id
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_id: A list of vuln_id
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnFilter",
                            key="VULN_ID",
                            value=vuln_id,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vuln_severity", [
    ["1", "2", "3", "4", "5"]
])
def test_show_host_vulnerability_severity(api_v1_client, vuln_severity):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability->Severity

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_severity: A list of vuln_severity
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnFilter",
                            key="SEVERITY",
                            value=vuln_severity,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vuln_risk_score", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO

])
def test_show_host_vulnerability_risk_score(api_v1_client, vuln_risk_score, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability->Risk Score

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability->Risk Score
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_risk_score: Risk Score
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnFilter",
                            key="VULN_RISK_SCORE",
                            value=vuln_risk_score,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vuln_description", [
    "abc",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.STARTS_WITH

])
def test_show_host_vulnerability_description(api_v1_client, vuln_description, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability->Description

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability->Description
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_description: Description
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnFilter",
                            key="DESCRIPTION",
                            value=vuln_description,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vuln_exploit", [
    "true",
    "false"
])
def test_show_host_vulnerability_exploit(api_v1_client, vuln_exploit):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability->Exploit Available

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability->Exploit Available
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_exploit: Exploit Available option
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnFilter",
                            key="PUBLIC_EXPLOIT_AVAILABLE",
                            value=vuln_exploit,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("host_name", [
    "i-",
    "i-123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.STARTS_WITH

])
def test_show_host_hostname(api_v1_client, host_name, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Hostname

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Hostname
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        host_name: Hostname
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="HOST_NAME",
                            value=host_name,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("machine_status", [
    ["2", "1"],
    ["123"]
])
def test_show_host_machine_status(api_v1_client, machine_status):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Machine Status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Machine Status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        machine_status: Machine Status
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="MACHINE_STATUS",
                            value=machine_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("internet_exposed", [
    "true",
    "false"
])
def test_show_host_internet_exposed(api_v1_client, internet_exposed):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Internet Exposed

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Internet Exposed
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        internet_exposed: Internet Exposed option
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="INTERNET_EXPOSED",
                            value=internet_exposed,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("account_id", [
    "886436945382"
])
def test_show_host_account_id(api_v1_client, account_id):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Account ID

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Account ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        account_id: Cloud Account Id
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="ACCOUNT_ID",
                            value=account_id,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("account_alias", [
    "cnapp"
])
def test_show_host_account_alias(api_v1_client, account_alias):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Account Alias

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Account Alias
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        account_alias: Cloud Account Alias
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="ACCOUNT_ALIAS",
                            value=account_alias,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("organization_id", [
    "cnapp-445301"
])
def test_show_host_organization_id(api_v1_client, organization_id):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Organization ID

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Organization ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        organization_id: Organization Id
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="ORGANIZATION_ID",
                            value=organization_id,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("avd_enabled", [
    "true",
    "false"
])
def test_show_host_avd_enabled(api_v1_client, avd_enabled):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->AVD Enabled

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->AVD Enabled
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        avd_enabled: AVD Enabled option
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="AVD_ENABLED",
                            value=avd_enabled,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("coverage_type", [
    ["Agent", "Agentless"],
    ["Agent and Agentless"],
    ["123"]
])
def test_show_host_coverage_type(api_v1_client, coverage_type):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Coverage Type

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Coverage Type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        coverage_type: Coverage types
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="COVERAGE_TYPE",
                            value=coverage_type,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("external_ip", [
    "100.26.111.81",
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_external_ip(api_v1_client, external_ip, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->External IP

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->External IP
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        external_ip: External IP
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="EXTERNAL_IP",
                            value=external_ip,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("internal_ip", [
    "10.1.10.101",
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_internal_ip(api_v1_client, internal_ip, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Internal IP

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Internal IP
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        internal_ip: Internal IP
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="INTERNAL_IP",
                            value=internal_ip,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("tag_key_pair", [
    {"tag_name": "some_name", "tag_value": "some_value"},
    {"tag_name": "a"*128, "tag_value": "b"*256},
    {"tag_name": "spaces and + - = . _ : /", "tag_value": "spaces and + - = . _ : /"},
])
def test_show_host_machine_tag(api_v1_client, tag_key_pair):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Machine Tag

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Machine Tag
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        tag_key_pair: Machine Tag
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="MACHINE_TAGS",
                            value=tag_key_pair,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("machine_id", [
    "123",
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_host_machine_id(api_v1_client, machine_id, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Machine ID

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Machine ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        machine_id: Machine ID
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="MACHINE_ID",
                            value=machine_id,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_name", [
    ["Alpine Linux", "Amazon Linux", "Ubuntu"],
    ["123", "456"]
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_IN,
    ComparisonOperator.IS_NOT_ANY_OF
])
def test_show_host_os(api_v1_client, os_name, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_name: OS Name
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_NAME",
                            value=os_name,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_namespace", [
    ["amzn:2", "ubuntu:24.04"],
    ["123", "456"]
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_IN,
    ComparisonOperator.IS_NOT_ANY_OF
])
def test_show_host_os_namespace(api_v1_client, os_namespace, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS Namespace

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS Namespace
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_namespace: OS Namespace
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_NAMESPACE",
                            value=os_namespace,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_out_of_date", [
    "true",
    "false"
])
def test_show_host_os_out_of_date(api_v1_client, os_out_of_date):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS Out Of Date

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS Out Of Date
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_out_of_date: OS Out Of Date option
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_OUT_OF_DATE",
                            value=os_out_of_date,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_reboot_required", [
    "true",
    "false"
])
def test_show_host_os_reboot_required(api_v1_client, os_reboot_required):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS reboot Required

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS reboot Required
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_reboot_required: OS Reboot required optio
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_REBOOT_REQUIRED",
                            value=os_reboot_required,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_update_disabled", [
    "true",
    "false"
])
def test_show_host_os_update_disabled(api_v1_client, os_update_disabled):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS updates Disabled

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS updates Disabled
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_update_disabled: OS updates Disabled option
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_UPDATES_DISABLED",
                            value=os_update_disabled,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_type", [
    "Linux",
    "Windows"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_os_type(api_v1_client, os_type, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS Type

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS Type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_type: OS Type
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_TYPE",
                            value=os_type,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("os_version", [
    "24.04",
    "18.04",
    "18.04.6 LTS (Bionic Beaver)",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_os_version(api_v1_client, os_version, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->OS Version

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->OS Version
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        os_version: OS Version
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="OS_VERSION",
                            value=os_version,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("public_facing", [
    "true",
    "false"
])
def test_show_host_os_public_facing(api_v1_client, public_facing):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Public facing

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Public facing
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        public_facing: Public facing option
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="PUBLIC_FACING",
                            value=public_facing,
                            operator=ComparisonOperator.IS_ANY_OF)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("host_risk_score", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO

])
def test_show_host_risk_score(api_v1_client, host_risk_score, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Hosts->Risk Score

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Hosts->Risk Score
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        host_risk_score: Risk Score
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="HOST_RISK_SCORE",
                            value=host_risk_score,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("zone", [
    "us-east-1",
    "us-central",
    "us-east-1a",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_zone(api_v1_client, zone, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->Zone

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->Zone
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        zone: Host Zone
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="ZONE",
                            value=zone,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("ami", [
    "ami-0015077965ecb6387",
    "ami-",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_ami(api_v1_client, ami, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Host->AMI

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Host->AMI
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        ami: AMI
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="HostFilter",
                            key="MACHINE_IMAGE",
                            value=ami,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_name", [
    "PyYAML",
    "apache-log4j1.2",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_package_name(api_v1_client, package_name, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Package->Package/Application name

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Package->Package/Application name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_name: Package/Application Name
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_NAME",
                            value=package_name,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_name_space", [
    "alpine:v3.21",
    "amzn:2016.09",
    "python",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_package_name_space(api_v1_client, package_name_space, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Package->Package Namespace

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Package->Package Namespace
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_name_space: Package Namespace
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_NAMESPACE",
                            value=package_name_space,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_path", [
    "opt",
    "opt/java",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.STARTS_WITH,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_host_package_path(api_v1_client, package_path, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Package->Package Path

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Package->Package Path
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_path: Package Path
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnObservationFilters",
                            key="PACKAGE_PATH",
                            value=package_path,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_risk_score", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_host_package_risk_score(api_v1_client, package_risk_score, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Package->Risk Score

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Package->Risk Score
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_risk_score: Package Risk Score
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_RISK_SCORE",
                            value=package_risk_score,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_status", [
   ["1", "0"],
   ["-2", "-1"],
   ["-3", "2"]
])
def test_show_host_package_status(api_v1_client, package_status):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Package->Package Status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Package->Package Status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_status: Package Status
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnObservationFilters",
                            key="PACKAGE_STATUS",
                            value=package_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_version", [
    "0.0.12+nmu1",
    "123",
    "0.0.22"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.STARTS_WITH,
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.CONTAINS

])
def test_show_host_package_version(api_v1_client, package_version, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Package->Package/Application Version

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Package->Package/Application Version
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_version: Package/Application Version
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_VERSION",
                            value=package_version,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vulnerability_status_category", [
   ["1", "0"],
   ["-1", "-1"],
   ["-2", "2"]
])
def test_show_host_vulnerability_status_category(api_v1_client, vulnerability_status_category):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability Observation->Vulnerability status category

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability Observation->Vulnerability status category
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vulnerability_status_category: Vulnerability Status Category
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnObservationFilters",
                            key="STATUS_CATEGORY",
                            value=vulnerability_status_category,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vulnerability_status", [
   ["4", "3", "2", "1", "-1"],
   ["-2", "0"]
])
def test_show_host_vulnerability_status(api_v1_client, vulnerability_status):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability Observation->status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability Observation->status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vulnerability_status: Vulnerability Status
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnObservationFilters",
                            key="STATUS",
                            value=vulnerability_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("entity_vulnerability_status", [
   ["1", "-1", "0"],
   ["-2", "2"]
])
def test_show_host_entity_vulnerability_status(api_v1_client, entity_vulnerability_status):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability Observation->Entity Vulnerability Status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability Observation->status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        entity_vulnerability_status: Entity Status Category
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnObservationFilters",
                            key="ENTITY_STATUS_CATEGORY",
                            value=entity_vulnerability_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("entity_type", [
   ["HostMachine", "Image"],
   ["abc", "123"]
])
def test_show_host_entity_type(api_v1_client, entity_type):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Vulnerability Observation->Entity type

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Vulnerability Observation->Entity type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        entity_type: Entity Type
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="VulnObservationFilters",
                            key="ENTITY_TYPE",
                            value=entity_type,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("vulnerability_type", [
    "VULN_COUNT_CRITICAL",
    "VULN_COUNT_CRITICAL_FIXABLE",
    "VULN_COUNT_HIGH",
    "VULN_COUNT_HIGH_FIXABLE",
    "VULN_COUNT_INFO",
    "VULN_COUNT_INFO_FIXABLE",
    "VULN_COUNT_LOW",
    "VULN_COUNT_LOW_FIXABLE",
    "VULN_COUNT_MEDIUM",
    "VULN_COUNT_MEDIUM_FIXABLE",
    "VULN_COUNT_TOTAL",
    "VULN_COUNT_TOTAL_FIXABLE"
])
@pytest.mark.parametrize("number_of_vulnerabilities", [
    "1",
    "-1",
    "100.1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_host_total_vulnerabilities(api_v1_client, vulnerability_type, number_of_vulnerabilities, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Total Vulnerabilities ->{vulnerability_type}

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Total Vulnerabilities ->{vulnerability_type}
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vulnerability_type: Vulnerability Type
        number_of_vulnerabilities: Number of Vulnerability
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="TotalVulnFilter",
                            key=vulnerability_type,
                            value=number_of_vulnerabilities,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")


@pytest.mark.parametrize("package_type", [
    "PACKAGE_COUNT_EXCEPTION",
    "PACKAGE_COUNT_NOT_VULNERABLE",
    "PACKAGE_COUNT_VULNERABLE"
])
@pytest.mark.parametrize("number_of_packages", [
    "1",
    "-1",
    "100.1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_host_total_packages(api_v1_client, package_type, number_of_packages, operator):
    """
    Verify that New Vulnerability API returns status code 200 from HOST->Total Packages ->{package_type}

    Given: API V1 Client
    When: Call New Vulnerability API, using filter HOST->Total Packages ->{package_type}
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_type: Packages Type
        number_of_packages: Number of Packages
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    query_object.add_filter(type="TotalPackageFilter",
                            key=package_type,
                            value=number_of_packages,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="host")
