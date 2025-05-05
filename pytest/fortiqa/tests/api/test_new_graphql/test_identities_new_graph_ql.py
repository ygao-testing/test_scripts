import logging
import pytest

from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator, ResourceGroups, IdentityResourceTypesV2
from fortiqa.libs.lw.apiv1.helpers.new_graphql_helper import NewGraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.new_graph_ql.new_graph_ql import NewGraphQL
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL
from fortiqa.tests.api.test_new_graphql.conftest import compare_resource_ids

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_identities_by_severity(api_v1_client, severity, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Risk Score->Severity

    Given: API V1 Client, and a list of severity
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Risk Score->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="Severity",
                                           operator=ComparisonOperator.IS_ANY_OF,
                                           value=severity)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="severity",
                                           operator=ComparisonOperator.IS_IN,
                                           value=severity)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response_old = graph_api.exec_query(generated_payload)
    compare_resource_ids(response_old, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO, ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO])
@pytest.mark.parametrize("risk_score", [
    0,
    1,
    pytest.param("-123456", marks=pytest.mark.xfail(reason="Invalid input, expected type Float"))
])
def test_search_identities_by_score(api_v1_client, operator, risk_score, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Risk Score->Score

    Given: API V1 Client, comparision operator and risk score
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Risk Score->Severity->Critical and High
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        risk_score: Risk score, 0-10
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="Score",
                                           operator=operator,
                                           value=risk_score)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
    unifiedEntityRisk_filter.add_subfilter(key="score",
                                           operator=operator,
                                           value=risk_score)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("cloud_provider", [
    ['AWS', 'GCP', 'AZURE'],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_identities_by_cloud_service_provider(api_v1_client, cloud_provider, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Cloud Service Provider

    Given: API V1 Client, and a list of cloud service providers
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Cloud Service Provider
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        cloud_provider: A list of cloud providers. e.g: ['AWS', 'GCP', 'AZURE']
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="cloudProvider",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=cloud_provider)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="cloudServiceProvider",
                     operator=ComparisonOperator.IS_IN,
                     value=cloud_provider)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("account_alias", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_account_alias(api_v1_client, operator, account_alias, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Accounts->Account Alias

    Given: API V1 Client, comparision operator and account_alias
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Accounts->Account Alias
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        account_alias: Account Alias
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    accounts_filter = query.add_filter(key="account")
    accounts_filter.add_subfilter(key="Alias",
                                  operator=operator,
                                  value=account_alias)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    accounts_filter = query.add_filter(key="accounts")
    accounts_filter.add_subfilter(key="accountAlias",
                                  operator=operator,
                                  value=account_alias)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("account_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_account_id(api_v1_client, operator, account_id, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Accounts->Account ID

    Given: API V1 Client, comparision operator and account_id
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Accounts->Account ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        account_id: Account ID
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    accounts_filter = query.add_filter(key="account")
    accounts_filter.add_subfilter(key="Id",
                                  operator=operator,
                                  value=account_id)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    accounts_filter = query.add_filter(key="accounts")
    accounts_filter.add_subfilter(key="accountId",
                                  operator=operator,
                                  value=account_id)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("organization_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_organization_id(api_v1_client, operator, organization_id, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Accounts->Organization ID
    Given: API V1 Client, comparision operator and organization_id
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Accounts->Organization ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        organization_id: Organization ID
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    accounts_filter = query.add_filter(key="account")
    accounts_filter.add_subfilter(key="organizationId",
                                  operator=operator,
                                  value=organization_id)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    accounts_filter = query.add_filter(key="accounts")
    accounts_filter.add_subfilter(key="organizationId",
                                  operator=operator,
                                  value=organization_id)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("uniform_resource_name", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_uniform_resource_name(api_v1_client, operator, uniform_resource_name, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Accounts->Uniform Resource Name
    Given: API V1 Client, comparision operator and uniform_resource_name
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Accounts->Uniform Resource Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        uniform_resource_name: Uniform Resource Name, i.e arn in AWS resources
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="urn",
                     operator=operator,
                     value=uniform_resource_name)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="urn",
                     operator=operator,
                     value=uniform_resource_name)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("tag_key_pair", [
    {"tag_name": "some_name", "tag_value": "some_value"},
    {"tag_name": "a"*128, "tag_value": "b"*256},
    {"tag_name": "spaces and + - = . _ : /", "tag_value": "spaces and + - = . _ : /"},
])
def test_search_identities_by_tag_value(api_v1_client, tag_key_pair, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Tags

    Given: API V1 Client, and a list of tag name_value pairs
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Tags
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        tag_key_pair: A list of tag name_value pairs
    """
    graph_api = NewGraphQL(api_v1_client)
    tag_name = tag_key_pair['tag_name']
    tag_value = tag_key_pair['tag_value']
    tag_payload = [{
        "key": tag_name,
        "value": {
            "eq": tag_value
        }
    }]
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="resourceTags",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=tag_payload)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="tags",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=tag_payload)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("alert_id", [
    123,
    pytest.param(-123456, marks=pytest.mark.invalid_input_success),
    pytest.param("-123456", marks=pytest.mark.xfail(reason="Invalid Input, expected i64"))
])
def test_search_identities_alert_by_alert_id(api_v1_client, alert_id, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Alerts>Alert ID

    Given: API V1 Client, and alert_id
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Alerts>Alert ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        alert_id: Alert ID
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    alerts_filter = query.add_filter(key="alerts")
    alerts_filter.add_subfilter(key="alertId",
                                operator=ComparisonOperator.IS_EQUAL_TO,
                                value=alert_id)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    alerts_filter = query.add_filter(key="alerts")
    alerts_filter.add_subfilter(key="alertId",
                                operator=ComparisonOperator.IS_EQUAL_TO,
                                value=alert_id)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_identities_alert_by_severity(api_v1_client, severity, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Alerts>Severity

    Given: API V1 Client, and severity
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Alerts>Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    alerts_filter = query.add_filter(key="alerts")
    alerts_filter.add_subfilter(key="severity",
                                operator=ComparisonOperator.IS_ANY_OF,
                                value=severity)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    alerts_filter = query.add_filter(key="alerts")
    alerts_filter.add_subfilter(key="severity",
                                operator=ComparisonOperator.IS_IN,
                                value=severity)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("rule_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_compliance_by_alert_id(api_v1_client, rule_id, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Compliance Violation->Rule ID

    Given: API V1 Client, and rule_id
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Compliance Violation->Rule ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        rule_id: Rule ID
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    compliance_filter = query.add_filter(key="COMPLIANCE_OBSERVATION")
    compliance_filter.add_subfilter(key="ruleId",
                                    operator=ComparisonOperator.IS_EQUAL_TO,
                                    value=rule_id)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    compliance_filter = query.add_filter(key="complianceFindings")
    compliance_filter.add_subfilter(key="ruleId",
                                    operator=ComparisonOperator.IS_EQUAL_TO,
                                    value=rule_id)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("severity", [
    ["CRITICAL", "HIGH"],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    pytest.param(["TEST"], marks=pytest.mark.xfail(reason="Invalid input"))
])
def test_search_identities_compliance_by_severity(api_v1_client, severity, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Compliance Violation->Severity

    Given: API V1 Client, and severity
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Compliance Violation->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        severity: A list of severity
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    compliance_filter = query.add_filter(key="COMPLIANCE_OBSERVATION")
    compliance_filter.add_subfilter(key="severity",
                                    operator=ComparisonOperator.IS_ANY_OF,
                                    value=severity)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    compliance_filter = query.add_filter(key="complianceFindings")
    compliance_filter.add_subfilter(key="severity",
                                    operator=ComparisonOperator.IS_IN,
                                    value=severity)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("resource_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_resource_id(api_v1_client, operator, resource_id, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Resource ID

    Given: API V1 Client, comparision operator and resource_id
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Resource ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        resource_id: Resource ID
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="resourceId",
                     operator=operator,
                     value=resource_id)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="resourceId",
                     operator=operator,
                     value=resource_id)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("operator", [ComparisonOperator.IS_EQUAL_TO])
@pytest.mark.parametrize("resource_name", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
def test_search_identities_by_resource_name(api_v1_client, operator, resource_name, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Resource Name

    Given: API V1 Client, comparision operator and resource_name
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Resource Name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        operator: Comparison operator, e.g: is equal to
        resource_name: Resource Name
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="resourceName",
                     operator=operator,
                     value=resource_name)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="resourceName",
                     operator=operator,
                     value=resource_name)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("resource_group", [[ResourceGroups.ALL_AWS_RESOURCES, ResourceGroups.ALL_AZURE_RESOURCES]])
def test_search_identities_by_resource_group(api_v1_client, resource_group, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Resource Groups

    Given: API V1 Client, and a list of resource_groups
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Resource Groups
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_group: Resource Group
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    resource_group_values = list(map(lambda rg: rg.value, resource_group))
    query.add_filter(key="resourceGroupIds",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=resource_group_values)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    resource_group_values = list(map(lambda rg: rg.value, resource_group))
    query.add_filter(key="resourceGroupIds",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=resource_group_values)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("has_attack_path", [True, False])
def test_search_identities_by_has_attack_path(api_v1_client, has_attack_path, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Attack Path

    Given: API V1 Client, comparision operator and has_attack_path option
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Attack Path
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        has_attack_path: Attack Path options
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="hasAttackPath",
                     operator=ComparisonOperator.IS_EQUAL_TO,
                     value=has_attack_path)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="hasAttackPath",
                     value=has_attack_path)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("has_instance_id", [True, False])
def test_search_identities_by_has_lateral_ssh_movement(api_v1_client, has_instance_id, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Has Instance ID

    Given: API V1 Client, comparision operator and has_instance_id option
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Has Instance ID
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        has_instance_id: Lateral SSH Movement options
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    query.add_filter(key="hasInstanceProfile",
                     operator=ComparisonOperator.IS_EQUAL_TO,
                     value=has_instance_id)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
    graph_api = GraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY')
    query.add_filter(key="hasInstanceProfile",
                     value=has_instance_id)
    generated_payload = GraphQLHelper().generate_payload(query, start_time_string=get_explorer_time_range[0], end_time_string=get_explorer_time_range[1])
    response = graph_api.exec_query(generated_payload)
    compare_resource_ids(response, response_new)


@pytest.mark.parametrize("resource_type", [IdentityResourceTypesV2.all_resource_types()])
def test_search_identities_by_resource_type(api_v1_client, resource_type, get_explorer_time_range):
    """
    Verify that NewGraphQL API returns status code 200 from IDENTITY_RESOURCE->Resource Type

    Given: API V1 Client, and resource_type list
    When: Call NewGraphQL API, using filter IDENTITY_RESOURCE->Resource Type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_type: Resource type
    """
    graph_api = NewGraphQL(api_v1_client)
    query = GraphQLFilter(type='IDENTITY_RESOURCE')
    resource_group_values = [rg.value for rg in resource_type]
    query.add_filter(key="type",
                     operator=ComparisonOperator.IS_ANY_OF,
                     value=resource_group_values)
    generated_payload = NewGraphQLHelper().generate_payload(query)
    response_new = graph_api.exec_query(generated_payload)
    assert response_new.status_code == 200, f"Expected to get status code 200 from NewGraphQL API, but got err: {response_new.text}"
    assert "errors" not in response_new.json(), f"Expect no error returned, but got {response_new.json()['errors'][0]['message']}"
