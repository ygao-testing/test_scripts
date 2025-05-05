import logging
import pytest
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL

logger = logging.getLogger(__name__)


class TestExplorerAzureRoleDefinitions:

    def test_verify_find_all_role_definitions_in_explorer_vs_azure(
            self,
            api_v1_client,
            all_azure_roles,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """Verify if all Azure custom roles retrieved from Azure are present in the Explorer's response.

        Given:
            - A list of Azure custom roles retrieved from Azure.
            - A Lacework Explorer response containing resource details of type 'AZURE_AUTHORIZATION_ROLEDEFINITION'.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AZURE_AUTHORIZATION_ROLEDEFINITION'.

        Then:
            - All Azure custom roles retrieved from Azure should have their names present as resource IDs in the Explorer's response.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            all_azure_roles: A list of Azure custom roles retrieved from Azure.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        # Build resource IDs for all Azure roles
        azure_role_resource_ids = {role["name"] for role in all_azure_roles}

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AZURE_AUTHORIZATION_ROLEDEFINITION"])

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract resource IDs from Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        explorer_resource_ids = {edge.get("node", {}).get("resourceId")
                                 for edge in edges if edge.get("node", {}).get("resourceId")}

        # Verify all resource IDs from Azure are present in Explorer response
        logger.debug(f"azure_role_resource_ids: {azure_role_resource_ids}")
        logger.debug(f"explorer_resource_ids: {explorer_resource_ids}")
        missing_resource_ids = azure_role_resource_ids - explorer_resource_ids
        assert not missing_resource_ids, f"Missing resource IDs in Explorer response: {missing_resource_ids}\n Resource IDs in Explorer response: {explorer_resource_ids}"

    @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/PSP-3094 & https://lacework.atlassian.net/issues/RAIN-94244')
    def test_verify_find_all_role_definitions_in_explorer_vs_azure_filter_by_subscription_id(
            self,
            api_v1_client,
            azure_account,
            all_azure_roles,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """Verify if all Azure custom roles retrieved from Azure are present in the Explorer's response.

        Given:
            - A list of Azure custom roles retrieved from Azure.
            - A Lacework Explorer response containing resource details filtered by the Azure subscription and resource type.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AZURE_AUTHORIZATION_ROLEDEFINITION'
              for the specified subscription.

        Then:
            - All Azure custom roles retrieved from Azure should have their names present as resource IDs in the Explorer's response.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            azure_account: Azure account details.
            all_azure_roles: A list of Azure custom roles retrieved from Azure.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        # Build resource IDs for all Azure roles
        azure_role_resource_ids = {role["name"] for role in all_azure_roles}

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=azure_account.subscription_id,
        )
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AZURE_AUTHORIZATION_ROLEDEFINITION"])

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract resource IDs from Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        explorer_resource_ids = {edge.get("node", {}).get("resourceId")
                                 for edge in edges if edge.get("node", {}).get("resourceId")}

        # Verify all resource IDs from Azure are present in Explorer response
        logger.debug(f"azure_role_resource_ids: {azure_role_resource_ids}")
        logger.debug(f"explorer_resource_ids: {explorer_resource_ids}")
        missing_resource_ids = azure_role_resource_ids - explorer_resource_ids
        assert not missing_resource_ids, f"Missing resource IDs in Explorer response: {missing_resource_ids}\n Resource IDs in Explorer response: {explorer_resource_ids}"

    def test_verify_role_definition_by_resource_id_in_explorer(
            self,
            api_v1_client,
            random_role_instance,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """Verify if the Explorer response contains only the role definition matching the resourceId (name).

        Given:
            - An Azure custom role selected randomly with a known 'name' (resourceId).
            - A Lacework Explorer response filtered by:
                - Type: "IDENTITY".
                - ResourceId: The 'name' of the Azure custom role.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified filters and time period.

        Then:
            - The API should return a 200 status code.
            - The response should only contain the Azure custom role matching the provided 'resourceId'.
            - All 'resourceId' fields in the response should match the 'name' of the selected Azure custom role.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_role_instance: A randomly selected Azure custom role from the 'all_azure_roles' fixture.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest Explorer update time period in ISO 8601 format.
        """
        if not random_role_instance:
            pytest.skip("No role instance found")

        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")

        # Add resourceId filter (mapped to 'name')
        query.add_filter(
            key="resourceId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=random_role_instance["name"]
        )

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {response.json()['errors'][0]['message']}."
        response_json = response.json()

        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        resource_ids = {edge.get("node", {}).get(
            "resourceId") for edge in edges if edge.get("node", {}).get("resourceId")}

        assert resource_ids, f"No resourceIds found in the response. Expected all resourceIds to match {random_role_instance['name']}."

        assert (
            random_role_instance["name"] in resource_ids
        ), f"Expected role definition with resourceId {random_role_instance['name']} to be present in the response, but it was not found. Found: {resource_ids}."

        assert (
            len(resource_ids) == 1
        ), f"Unexpected resourceIds found. Expected only {random_role_instance['name']}, but found: {resource_ids}."

    @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/PSP-3096 & https://lacework.atlassian.net/browse/RAIN-94252')
    def test_verify_role_definition_by_urn_in_explorer(
            self,
            api_v1_client,
            random_role_instance,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """Verify if the Explorer response contains only the role definition matching the urn.

        Given:
            - An Azure custom role selected randomly with a known 'id' (urn).
            - A Lacework Explorer response filtered by:
                - Type: "IDENTITY".
                - urn: The 'id' of the Azure custom role.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified filters and time period.

        Then:
            - The API should return a 200 status code.
            - The response should only contain the Azure custom role matching the provided 'urn'.
            - All 'urn' fields in the response should match the 'id' of the selected Azure custom role.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_role_instance: A randomly selected Azure custom role from the 'all_azure_roles' fixture.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest Explorer update time period in ISO 8601 format.
        """
        if not random_role_instance:
            pytest.skip("No role instance found")
        urn_from_azure = random_role_instance["id"]
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")

        # Add urn filter (mapped to 'id')
        query.add_filter(
            key="urn",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=urn_from_azure
        )

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {response.json()['errors'][0]['message']}."
        response_json = response.json()

        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        urns = {edge.get("node", {}).get(
            "urn") for edge in edges if edge.get("node", {}).get("urn")}

        assert urns, f"No urns found in the response. Expected all urns to match {random_role_instance['id']}."

        assert (
            urn_from_azure in urns
        ), f"Expected role definition with urn {urn_from_azure} to be present in the response, but it was not found. Found: {urns}."

        assert (
            len(urns) == 1
        ), f"Unexpected urns found. Expected only {urn_from_azure}, but found: {urns}."
