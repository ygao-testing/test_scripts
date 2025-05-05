import logging
import pytest

from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator, ResourceGroups, IdentityResourceTypes
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_identities_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Risk Score->Severity

    Given: API V1 Client, and a list of severity
    When: Call GraphQL API, using filter IDENTITY->Risk Score->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="severity",
                                           operator=ComparisonOperator.IS_IN,
                                           value=severity)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO, ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO])
@pytest.mark.parametrize("risk_score", [
    0,
    1,
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_score(api_v1_client, operator, risk_score):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Risk Score->Score

    Given: API V1 Client, comparision operator and risk score
    When: Call GraphQL API, using filter IDENTITY->Risk Score->Severity->Critical and High
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        risk_score: Risk score, 0-10
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_cloud_service_provider(api_v1_client, cloud_provider):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Cloud Service Provider

    Given: API V1 Client, and a list of cloud service providers
    When: Call GraphQL API, using filter IDENTITY->Cloud Service Provider
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        cloud_provider: A list of cloud providers. e.g: ['AWS', 'GCP', 'AZURE']
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_account_alias(api_v1_client, operator, account_alias):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Accounts->Account Alias

    Given: API V1 Client, comparision operator and account_alias
    When: Call GraphQL API, using filter IDENTITY->Accounts->Account Alias
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        account_alias: Account Alias
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_account_id(api_v1_client, operator, account_id):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Accounts->Account ID

    Given: API V1 Client, comparision operator and account_id
    When: Call GraphQL API, using filter IDENTITY->Accounts->Account ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        account_id: Account ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_organization_id(api_v1_client, operator, organization_id):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Accounts->Organization ID
    Given: API V1 Client, comparision operator and organization_id
    When: Call GraphQL API, using filter IDENTITY->Accounts->Organization ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        organization_id: Organization ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_uniform_resource_name(api_v1_client, operator, uniform_resource_name):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Accounts->Uniform Resource Name
    Given: API V1 Client, comparision operator and uniform_resource_name
    When: Call GraphQL API, using filter IDENTITY->Accounts->Uniform Resource Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        uniform_resource_name: Uniform Resource Name, i.e arn in AWS resources
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_tag_value(api_v1_client, tag_key_pair):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Tags

    Given: API V1 Client, and a list of tag name_value pairs
    When: Call GraphQL API, using filter IDENTITY->Tags
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
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_alert_by_alert_id(api_v1_client, alert_id):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Alerts>Alert ID

    Given: API V1 Client, and alert_id
    When: Call GraphQL API, using filter IDENTITY->Alerts>Alert ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        alert_id: Alert ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_alert_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Alerts>Severity

    Given: API V1 Client, and severity
    When: Call GraphQL API, using filter IDENTITY->Alerts>Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_compliance_by_alert_id(api_v1_client, rule_id):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Compliance Violation->Rule ID

    Given: API V1 Client, and rule_id
    When: Call GraphQL API, using filter IDENTITY->Compliance Violation->Rule ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        rule_id: Rule ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_compliance_by_severity(api_v1_client, severity):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Compliance Violation->Severity

    Given: API V1 Client, and severity
    When: Call GraphQL API, using filter IDENTITY->Compliance Violation->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_resource_id(api_v1_client, operator, resource_id):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Resource ID

    Given: API V1 Client, comparision operator and resource_id
    When: Call GraphQL API, using filter IDENTITY->Resource ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        resource_id: Resource ID
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
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
def test_search_identities_by_resource_name(api_v1_client, operator, resource_name):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Resource Name

    Given: API V1 Client, comparision operator and resource_name
    When: Call GraphQL API, using filter IDENTITY->Resource Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        resource_name: Resource Name
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="resourceName",
                     operator=operator,
                     value=resource_name)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("resource_group", [[ResourceGroups.ALL_AWS_RESOURCES, ResourceGroups.ALL_AZURE_RESOURCES]])
def test_search_identities_by_resource_group(api_v1_client, resource_group):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Resource Groups

    Given: API V1 Client, and a list of resource_groups
    When: Call GraphQL API, using filter IDENTITY->Resource Groups
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_group: Resource Group
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    resource_group_values = list(map(lambda rg: rg.value, resource_group))
    query.add_filter(key="resourceGroupIds",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=resource_group_values)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("has_attack_path", [True, False])
def test_search_identities_by_has_attack_path(api_v1_client, has_attack_path):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Attack Path

    Given: API V1 Client, comparision operator and has_attack_path option
    When: Call GraphQL API, using filter IDENTITY->Attack Path
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        has_attack_path: Attack Path options
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="hasAttackPath",
                     value=has_attack_path)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("has_instance_id", [True, False])
def test_search_identities_by_has_lateral_ssh_movement(api_v1_client, has_instance_id):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Has Instance ID

    Given: API V1 Client, comparision operator and has_instance_id option
    When: Call GraphQL API, using filter IDENTITY->Has Instance ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        has_instance_id: Lateral SSH Movement options
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="hasInstanceProfile",
                     value=has_instance_id)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"


@pytest.mark.parametrize("resource_type", [IdentityResourceTypes.all_resource_types()])
def test_search_identities_by_resource_type(api_v1_client, resource_type):
    """
    Verify that GraphQL API returns status code 200 from IDENTITY->Resource Type

    Given: API V1 Client, and resource_type list
    When: Call GraphQL API, using filter IDENTITY->Resource Type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_type: Resource type
    """
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    resource_group_values = [rg.value for rg in resource_type]
    query.add_filter(key="resourceType",
                     operator=ComparisonOperator.IS_IN,
                     value=resource_group_values)
    generated_payload = GraphQLHelper().generate_payload(query)
    response = graph_api.exec_query(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {response.text}"
    assert "errors" not in response.json(), f"Expect no error returned, but got {response.json()['errors'][0]['message']}"
