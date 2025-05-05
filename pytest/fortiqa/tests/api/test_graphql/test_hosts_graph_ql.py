import logging
import pytest

from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator, ResourceGroups
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_hosts_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from HOST->Risk Score->Severity

    Given: API V1 Client, and a list of severity
    When: Call GraphQL API, using filter HOST->Risk Score->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="severity",
                                           operator=ComparisonOperator.IS_IN,
                                           value=severity)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO
])
@pytest.mark.parametrize("risk_score", [
    0,
    1,
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_score(api_v1_client, operator, risk_score):
    """
    Verify that GraphQL API returns status code 200 from HOST->Risk Score->Score

    Given: API V1 Client, comparision operator and risk score
    When: Call GraphQL API, using filter HOST->Risk Score->Severity->Critical and High
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        risk_score: Risk score, 0-10
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="score",
                                           operator=operator,
                                           value=risk_score)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("cloud_provider", [
    ['AWS', 'GCP', 'AZURE'],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_hosts_by_cloud_service_provider(api_v1_client, cloud_provider):
    """
    Verify that GraphQL API returns status code 200 from HOST->Cloud Service Provider

    Given: API V1 Client, and a list of cloud service providers
    When: Call GraphQL API, using filter HOST->Cloud Service Provider
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        cloud_provider: A list of cloud providers. e.g: ['AWS', 'GCP', 'AZURE']
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="cloudServiceProvider",
                     operator=ComparisonOperator.IS_IN,
                     value=cloud_provider)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("account_alias", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_account_alias(api_v1_client, operator, account_alias):
    """
    Verify that GraphQL API returns status code 200 from HOST->Accounts->Account Alias

    Given: API V1 Client, comparision operator and account_alias
    When: Call GraphQL API, using filter HOST->Accounts->Account Alias
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        account_alias: Account Alias
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    accounts_filter = query.add_filter(key="accounts")
    accounts_filter.add_subfilter(key="accountAlias",
                                  operator=operator,
                                  value=account_alias)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("account_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_account_id(api_v1_client, operator, account_id):
    """
    Verify that GraphQL API returns status code 200 from HOST->Accounts->Account ID

    Given: API V1 Client, comparision operator and account_id
    When: Call GraphQL API, using filter HOST->Accounts->Account ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        account_id: Account ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    accounts_filter = query.add_filter(key="accounts")
    accounts_filter.add_subfilter(key="accountId",
                                  operator=operator,
                                  value=account_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("organization_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_organization_id(api_v1_client, operator, organization_id):
    """
    Verify that GraphQL API returns status code 200 from HOST->Accounts->Organization ID
    Given: API V1 Client, comparision operator and organization_id
    When: Call GraphQL API, using filter HOST->Accounts->Organization ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        organization_id: Organization ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    accounts_filter = query.add_filter(key="accounts")
    accounts_filter.add_subfilter(key="organizationId",
                                  operator=operator,
                                  value=organization_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("uniform_resource_name", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_uniform_resource_name(api_v1_client, operator, uniform_resource_name):
    """
    Verify that GraphQL API returns status code 200 from HOST->Accounts->Uniform Resource Name
    Given: API V1 Client, comparision operator and uniform_resource_name
    When: Call GraphQL API, using filter HOST->Accounts->Uniform Resource Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        uniform_resource_name: Uniform Resource Name, i.e arn in AWS resources
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="urn",
                     operator=operator,
                     value=uniform_resource_name)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("tag_key_pair", [
    {"tag_name": "some_name", "tag_value": "some_value"},
    {"tag_name": "a"*128, "tag_value": "b"*256},
    {"tag_name": "spaces and + - = . _ : /", "tag_value": "spaces and + - = . _ : /"},
])
def test_search_hosts_by_tag_value(api_v1_client, tag_key_pair):
    """
    Verify that GraphQL API returns status code 200 from HOST->Tags

    Given: API V1 Client, and a list of tag name_value pairs
    When: Call GraphQL API, using filter HOST->Tags
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        tag_key_pair: A list of tag name_value pairs
    """
    graph_api = GraphQL(api_v1_client)
    tag_name = tag_key_pair['tag_name']
    tag_value = tag_key_pair['tag_value']
    tag_payload = [{
        "key": tag_name,
        "value": {
            "eq": tag_value
        }
    }]
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="tags",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=tag_payload)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("alert_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_alert_by_alert_id(api_v1_client, alert_id):
    """
    Verify that GraphQL API returns status code 200 from HOST->Alerts>Alert ID

    Given: API V1 Client, and alert_id
    When: Call GraphQL API, using filter HOST->Alerts>Alert ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        alert_id: Alert ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    alerts_filter = query.add_filter(key="alerts")
    alerts_filter.add_subfilter(key="alertId",
                                operator=ComparisonOperator.IS_EQUAL_TO,
                                value=alert_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_hosts_alert_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from HOST->Alerts>Severity

    Given: API V1 Client, and severity
    When: Call GraphQL API, using filter HOST->Alerts>Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    alerts_filter = query.add_filter(key="alerts")
    alerts_filter.add_subfilter(key="severity",
                                operator=ComparisonOperator.IS_IN,
                                value=severity)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("rule_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_compliance_by_alert_id(api_v1_client, rule_id):
    """
    Verify that GraphQL API returns status code 200 from HOST->Compliance Violation->Rule ID

    Given: API V1 Client, and rule_id
    When: Call GraphQL API, using filter HOST->Compliance Violation->Rule ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        rule_id: Rule ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    compliance_filter = query.add_filter(key="complianceFindings")
    compliance_filter.add_subfilter(key="ruleId",
                                    operator=ComparisonOperator.IS_EQUAL_TO,
                                    value=rule_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_hosts_compliance_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from HOST->Compliance Violation->Severity

    Given: API V1 Client, and severity
    When: Call GraphQL API, using filter HOST->Compliance Violation->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    compliance_filter = query.add_filter(key="complianceFindings")
    compliance_filter.add_subfilter(key="severity",
                                    operator=ComparisonOperator.IS_IN,
                                    value=severity)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("resource_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_resource_id(api_v1_client, operator, resource_id):
    """
    Verify that GraphQL API returns status code 200 from HOST->Resource ID

    Given: API V1 Client, comparision operator and resource_id
    When: Call GraphQL API, using filter HOST->Resource ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        resource_id: Resource ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="resourceId",
                     operator=operator,
                     value=resource_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("resource_name", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_resource_name(api_v1_client, operator, resource_name):
    """
    Verify that GraphQL API returns status code 200 from HOST->Resource Name

    Given: API V1 Client, comparision operator and resource_name
    When: Call GraphQL API, using filter HOST->Resource Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        resource_name: Resource Name
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="resourceName",
                     operator=operator,
                     value=resource_name)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("resource_group", [[ResourceGroups.ALL_AWS_RESOURCES, ResourceGroups.ALL_AZURE_RESOURCES]])
def test_search_hosts_by_resource_group(api_v1_client, resource_group):
    """
    Verify that GraphQL API returns status code 200 from HOST->Resource Groups

    Given: API V1 Client, and a list of resource_groups
    When: Call GraphQL API, using filter HOST->Resource Groups
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_group: Resource Group
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    resource_group_values = list(map(lambda rg: rg.value, resource_group))
    query.add_filter(key="resourceGroupIds",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=resource_group_values)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("internet_exposed", [True, False])
def test_search_hosts_by_internet_expose(api_v1_client, internet_exposed):
    """
    Verify that GraphQL API returns status code 200 from HOST->Internet Exposed

    Given: API V1 Client, comparision operator and internet_exposed option
    When: Call GraphQL API, using filter HOST->Internet Exposed
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        internet_exposed: Internet Exposed options
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="internetExposed",
                     value=internet_exposed)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("has_attack_path", [True, False])
def test_search_hosts_by_has_attack_path(api_v1_client, has_attack_path):
    """
    Verify that GraphQL API returns status code 200 from HOST->Attack Path

    Given: API V1 Client, comparision operator and has_attack_path option
    When: Call GraphQL API, using filter HOST->Attack Path
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        has_attack_path: Attack Path options
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="hasAttackPath",
                     value=has_attack_path)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_ANY_OF])
@pytest.mark.parametrize("cidr_range", [
    "198.51.100.2/24",
    pytest.param("123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_internet_exposed_to_cidr_range(api_v1_client, operator, cidr_range):
    """
    Verify that GraphQL API returns status code 200 from HOST->Internet Exposed to CIDR Range

    Given: API V1 Client, comparision operator and cidr
    When: Call GraphQL API, using filter HOST->Internet Exposed to CIDR Range
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        cidr_range: CIDR range
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="accessibleFromNetworkRangeV2",
                     operator=operator,
                     value=[cidr_range])
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("has_lateral_ssh_movement", [True, False])
def test_search_hosts_by_has_lateral_ssh_movement(api_v1_client, has_lateral_ssh_movement):
    """
    Verify that GraphQL API returns status code 200 from HOST->Lateral SSH Movement

    Given: API V1 Client, comparision operator and has_lateral_ssh_movement option
    When: Call GraphQL API, using filter HOST->Lateral SSH Movement
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        has_lateral_ssh_movement: Lateral SSH Movement options
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="hasLateralSshMovement",
                     value=has_lateral_ssh_movement)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_ANY_OF])
@pytest.mark.parametrize("open_port", [
    "8000",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_open_port(api_v1_client, operator, open_port):
    """
    Verify that GraphQL API returns status code 200 from HOST->Open Ports

    Given: API V1 Client, comparision operator and open_port
    When: Call GraphQL API, using filter HOST->Open Ports
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        open_port: Open ports
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="openPortsV2",
                     operator=operator,
                     value=[open_port])
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("hostname", [
    "123",
    pytest.param("123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_hostname(api_v1_client, operator, hostname):
    """
    Verify that GraphQL API returns status code 200 from HOST->Hostname

    Given: API V1 Client, comparision operator and hostname
    When: Call GraphQL API, using filter HOST->Hostname
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        hostname: Hostname
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="hostname",
                     operator=operator,
                     value=hostname)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("vuln_id", [
    "CVE-2022-29599",
    pytest.param("123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_vuln_by_id(api_v1_client, vuln_id):
    """
    Verify that GraphQL API returns status code 200 from HOST->Vulnerabilities->Vulnerability ID

    Given: API V1 Client, and vulnerability ID
    When: Call GraphQL API, using filter HOST->Vulnerabilities->Vulnerability ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_id: Vulnerability ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
    vulnerabilities_filter.add_subfilter(key="vulnId",
                                         operator=ComparisonOperator.IS_EQUAL_TO,
                                         value=vuln_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_hosts_vuln_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from HOST->Vulnerabilities->Severity

    Given: API V1 Client, and severity
    When: Call GraphQL API, using filter HOST->Vulnerabilities->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
    vulnerabilities_filter.add_subfilter(key="severity",
                                         operator=ComparisonOperator.IS_IN,
                                         value=severity)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("package_status", [
    ["ACTIVE", "INACTIVE"],
    ["ACTIVE", "INACTIVE", "UNKNOWN", "NO_AGENT_AVAILABLE"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_hosts_vuln_by_package_status(api_v1_client, package_status):
    """
    Verify that GraphQL API returns status code 200 from HOST->Vulnerabilities->Package Status

    Given: API V1 Client, and package status
    When: Call GraphQL API, using filter HOST->Vulnerabilities->Package Status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_status: A list of package_status
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
    vulnerabilities_filter.add_subfilter(key="packageStatus",
                                         operator=ComparisonOperator.IS_IN,
                                         value=package_status)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("package_name", [
    "openssh",
    pytest.param("TEST", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_vuln_by_package_name(api_v1_client, operator, package_name):
    """
    Verify that GraphQL API returns status code 200 from HOST->Vulnerabilities->Package Name

    Given: API V1 Client, comparision operator and package name
    When: Call GraphQL API, using filter HOST->Vulnerabilities->Package Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        package_name: Package name
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
    vulnerabilities_filter.add_subfilter(key="packageName",
                                         operator=ComparisonOperator.IS_EQUAL_TO,
                                         value=package_name)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("ip_addresses", [
    ["1.2.3.4", "4.3.2.1"],
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_hosts_by_ip_addresses(api_v1_client, ip_addresses):
    """
    Verify that GraphQL API returns status code 200 from HOST->IP Address

    Given: API V1 Client, comparision operator and a list of IP Addresses
    When: Call GraphQL API, using filter HOST->IP Address
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        ip_addresses: A list of IP Addresses
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='COMPUTE')
    query.add_filter(key="ipAddress",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=ip_addresses)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"
