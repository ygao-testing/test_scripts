import logging
import pytest
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL

logger = logging.getLogger(__name__)


class TestExplorerAzureVMs:

    def test_verify_find_all_vms_in_explorer_vs_azure(
            self,
            api_v1_client,
            azure_account,
            all_azure_vms,
            ingestion_tag,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """ Verify if all Azure VMs retrieved from Azure are present in the Explorer's response, optionally filtered by ingestion tags.

        Given:
            - A list of Azure VMs retrieved from Azure.
            - A Lacework Explorer response containing resource details filtered by the Azure subscription and resource type.
            - An optional ingestion tag to filter resources in the Explorer's response.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AZURE_COMPUTE_VM' for the specified subscription,
              optionally filtered by tags.

        Then:
            - All Azure VMs retrieved from Azure should have their IDs present as URNs in the Explorer's response.
            - No extra URNs should be present in the Explorer's response that are not part of the Azure VMs.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            azure_account: Azure account details.
            all_azure_vms: A list of Azure VMs retrieved from Azure.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tag in the Explorer's query.
                        If None, no filtering is applied in the query.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        # Build URNs for all Azure VMs and convert them to lower case
        azure_vm_urns = {vm["id"].lower() for vm in all_azure_vms}

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="COMPUTE")
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=azure_account.subscription_id,
        )
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AZURE_COMPUTE_VM"])
        if ingestion_tag:
            tag_payload = [{"key": key, "value": {"eq": value}}
                           for key, value in ingestion_tag.items()]
            query.add_filter(
                key="tags", operator=ComparisonOperator.IS_ANY_OF, value=tag_payload)

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {
            response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {
            response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract URNs from Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        explorer_urns = {edge.get("node", {}).get("urn")
                         for edge in edges if edge.get("node", {}).get("urn")}
        # Verify all URNs from Azure are present in Explorer response
        logger.debug(f"azure_vm_urns: {azure_vm_urns}")
        logger.debug(f"explorer_urns: {explorer_urns}")
        missing_urns = azure_vm_urns - explorer_urns
        assert not missing_urns, f"Missing URNs in Explorer response: {missing_urns}\n URNs in Explorer response: {explorer_urns}"
        # Verify Explorer does not contain unexpected URNs
        unexpected_urns = explorer_urns - azure_vm_urns
        assert not unexpected_urns, f"Unexpected URNs in Explorer response: {
            unexpected_urns}"

    def test_verify_find_all_vms_in_explorer_vs_azure_filter_by_subscription_id(
            self,
            api_v1_client,
            azure_account,
            all_azure_vms,
            ingestion_tag,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """ Verify if all Azure VMs retrieved from Azure are present in the Explorer's response, optionally filtered by ingestion tags.

        Given:
            - A list of Azure VMs retrieved from Azure.
            - A Lacework Explorer response containing resource details filtered by the Azure subscription and resource type.
            - An optional ingestion tag to filter resources in the Explorer's response.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AZURE_COMPUTE_VM' for the specified subscription,
              optionally filtered by tags.

        Then:
            - All Azure VMs retrieved from Azure should have their IDs present as URNs in the Explorer's response.
            - No extra URNs should be present in the Explorer's response that are not part of the Azure VMs.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            azure_account: Azure account details.
            all_azure_vms: A list of Azure VMs retrieved from Azure.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tag in the Explorer's query.
                        If None, no filtering is applied in the query.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        # Build URNs for all Azure VMs and convert them to lower case
        azure_vm_urns = {vm["id"].lower() for vm in all_azure_vms}

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="COMPUTE")
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=azure_account.subscription_id,
        )
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AZURE_COMPUTE_VM"])
        if ingestion_tag:
            tag_payload = [{"key": key, "value": {"eq": value}}
                           for key, value in ingestion_tag.items()]
            query.add_filter(
                key="tags", operator=ComparisonOperator.IS_ANY_OF, value=tag_payload)

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {
            response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {
            response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract URNs from Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        explorer_urns = {edge.get("node", {}).get("urn")
                         for edge in edges if edge.get("node", {}).get("urn")}
        # Verify all URNs from Azure are present in Explorer response
        logger.debug(f"azure_vm_urns: {azure_vm_urns}")
        logger.debug(f"explorer_urns: {explorer_urns}")
        missing_urns = azure_vm_urns - explorer_urns
        assert not missing_urns, f"Missing URNs in Explorer response: {missing_urns}\n URNs in Explorer response: {explorer_urns}"
        # Verify Explorer does not contain unexpected URNs
        unexpected_urns = explorer_urns - azure_vm_urns
        assert not unexpected_urns, f"Unexpected URNs in Explorer response: {
            unexpected_urns}"

    @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/PSP-3096')
    def test_verify_vm_by_urn_in_explorer(
            self,
            api_v1_client,
            random_vm_instance,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure):
        """Verify if the Azure VM is present in the Explorer by searching with the URN.

        Given:
            - An Azure VM selected randomly with a known URN (VM ID).
            - A Lacework Explorer response filtered by:
            - Type: "COMPUTE".
            - URN: The ID of the Azure VM.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified URN and type within the latest time period.

        Then:
            - The API should return a 200 status code.
            - All 'urn' fields in the response should match the ID of the selected Azure VM.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_vm_instance: A randomly selected Azure VM with its attributes, including its ID.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="COMPUTE")

        # Add URN filter
        query.add_filter(
            key="urn", operator=ComparisonOperator.IS_EQUAL_TO, value=random_vm_instance["id"])

        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period[
                "startTime"], end_time_string=latest_update_period["endTime"]
        )
        response = graph_api.exec_query(generated_payload)

        # Validate response
        assert response.status_code == 200, f"Expected 200 status code but got {
            response.status_code}."
        logger.debug(f"Explorer response: \n {response.json()}")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {
            response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract URNs from the response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        urns = {edge.get("node", {}).get("urn")
                for edge in edges if edge.get("node", {}).get("urn")}

        assert urns, f"No URNs found in the response. Expected all URNs to match {
            random_vm_instance['id']}."
        assert (
            random_vm_instance["id"] in urns
        ), f"Expected Azure VM with URN {random_vm_instance['id']} to be present in the response, but it was not found. Found: {urns}."
        assert (
            len(urns) == 1
        ), f"Unexpected URNs found. Expected only {random_vm_instance['id']}, but found: {urns}."

    def test_verify_vm_by_resource_id_in_explorer(
            self,
            api_v1_client,
            random_vm_instance,
            azure_account,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure
    ):
        """Verify if the Explorer response contains only the VM matching the resourceId (name).

        Given:
            - An Azure VM selected randomly with a known 'name' (resourceId).
            - A Lacework Explorer response filtered by:
                - Type: "COMPUTE".
                - Accounts: Specific Azure subscription ID.
                - ResourceType: "AZURE_COMPUTE_VM".
                - ResourceId: The name of the Azure VM.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified filters and time period.

        Then:
            - The API should return a 200 status code.
            - The response should only contain the Azure VM matching the provided 'resourceId'.
            - All 'resourceId' fields in the response should match the 'name' of the selected Azure VM.
            - If no match is found using 'name', retry with 'vm_id'. If found with 'vm_id', mark the test as 'xfail' with reference to PSP-3163. Otherwise, fail.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_vm_instance: A randomly selected Azure VM from the 'all_azure_vms' fixture.
            azure_account: Azure account details, including subscription ID.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest Explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure
        graph_api = GraphQL(api_v1_client)

        def query_lacework_by_resource_id(resource_id):
            """Helper function to query Lacework by a given resourceId."""
            query = GraphQLFilter(type="COMPUTE")
            query.add_filter(key="resourceType", operator=ComparisonOperator.IS_IN, value=["AZURE_COMPUTE_VM"])
            query.add_filter(key="resourceId", operator=ComparisonOperator.IS_EQUAL_TO, value=resource_id)
            generated_payload = GraphQLHelper().generate_payload(
                query, start_time_string=latest_update_period[
                    "startTime"], end_time_string=latest_update_period["endTime"]
            )
            response = graph_api.exec_query(generated_payload)
            assert response.status_code == 200, f"Expected 200 status code but got {response.status_code}."
            assert "errors" not in response.json(), (
                f"Expected no errors in response, but got {response.json()['errors'][0]['message']}."
            )

            return response.json().get("data", {}).get("resources", {}).get("edges", [])

        # Step 1: Query by name
        logger.info(f"Querying Lacework Explorer using resourceId: {random_vm_instance['name']}")
        edges = query_lacework_by_resource_id(random_vm_instance["name"])

        resource_ids = {edge.get("node", {}).get("resourceId") for edge in edges if edge.get("node", {}).get("resourceId")}
        if resource_ids:
            # Found match using 'name', proceed with validation
            assert len(resource_ids) == 1, f"Unexpected resourceIds found. Expected only {random_vm_instance['name']}, but found: {resource_ids}."
            assert random_vm_instance["name"] in resource_ids, f"Expected VM with resourceId {random_vm_instance['name']} but found {resource_ids}."
            return  # Test passes

        # Step 2: Query by vm_id if 'name' was not found
        logger.warning(f"No match found using name {random_vm_instance['name']}. Retrying with vm_id: {random_vm_instance['vm_id']}")
        edges = query_lacework_by_resource_id(random_vm_instance["vm_id"])
        resource_ids = {edge.get("node", {}).get("resourceId") for edge in edges if edge.get("node", {}).get("resourceId")}
        if resource_ids:
            # Found match using 'vm_id', mark test as 'xfail' with reference to PSP-3163
            pytest.xfail(f"Lacework used vm_id ({random_vm_instance['vm_id']}) instead of name ({random_vm_instance['name']}). "
                         "This is a known issue tracked in PSP-3163: https://lacework.atlassian.net/browse/PSP-3163.")

        # If neither name nor vm_id works, fail the test
        assert False, f"Neither name ({random_vm_instance['name']}) nor vm_id ({random_vm_instance['vm_id']}) matched in Lacework API."
