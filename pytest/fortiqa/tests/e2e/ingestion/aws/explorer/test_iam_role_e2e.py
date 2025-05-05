import logging
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL


logger = logging.getLogger(__name__)


class TestExplorerIAMRoles:
    def test_verify_find_all_iam_roles_in_explorer_vs_aws(
            self,
            api_v1_client,
            aws_account,
            all_aws_iam_roles,
            ingestion_tag,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if all IAM roles retrieved from AWS are present in the Explorer's response, optionally filtered by ingestion tags.

        Given:
            - A list of IAM roles retrieved from AWS.
            - A Lacework Explorer response containing resource details filtered by the AWS account and resource type.
            - An optional ingestion tag to filter resources in the Explorer's response.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AWS_IAM_ROLE' for the specified account,
              optionally filtered by tags.

        Then:
            - All IAM roles retrieved from AWS should have their ARNs present as URNs in the Explorer's response.
            - No extra URNs should be present in the Explorer's response that are not part of the AWS IAM roles.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            aws_account: AWS account details.
            all_aws_iam_roles: A list of IAM roles retrieved from AWS.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tag in the Explorer's query.
                        If None, no filtering is applied in the query.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        # Build URNs for all IAM roles
        aws_iam_role_urns = {role.arn for role in all_aws_iam_roles}

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=aws_account.aws_account_id,
        )
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AWS_IAM_ROLE"])
        tags = ingestion_tag
        if tags:
            tag_payload = [{"key": key, "value": {"eq": value}}
                           for key, value in tags.items()]

            query.add_filter(key="tags",
                             operator=ComparisonOperator.IS_ANY_OF,
                             value=tag_payload)

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
        # Verify all URNs from AWS are present in Explorer response
        missing_urns = aws_iam_role_urns - explorer_urns
        assert not missing_urns, f"Missing URNs in Explorer response: {
            missing_urns}"

        # Verify Explorer does not contain unexpected URNs
        unexpected_urns = explorer_urns - aws_iam_role_urns
        assert not unexpected_urns, f"Unexpected URNs in Explorer response: {
            unexpected_urns}"

    def test_verify_iam_role_by_urn_in_explorer(
            self,
            api_v1_client,
            random_iam_role,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if the IAM role is present in the Explorer by searching with the URN.

        Given:
            - An IAM role selected randomly from AWS with a known URN (role ARN).
            - A Lacework Explorer response filtered by:
            - Type: "IDENTITY".
            - URN: The ARN of the IAM role.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified URN and type within the latest time period.

        Then:
            - The API should return a 200 status code.
            - All 'urn' fields in the response should match the ARN of the selected IAM role.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_iam_role: A randomly selected IAM role with its attributes, including its ARN.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")

        # Add URN filter
        query.add_filter(key="urn",
                         operator=ComparisonOperator.IS_EQUAL_TO,
                         value=random_iam_role.arn)

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
        logger.info(f"Response from Explorer API:\n{response.json()}")
        response_json = response.json()

        # Extract URNs from the response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        urns = {edge.get("node", {}).get("urn")
                for edge in edges if edge.get("node", {}).get("urn")}

        assert urns, f"No URNs found in the response. Expected all URNs to match {
            random_iam_role.arn}."

        assert (
            random_iam_role.arn in urns
        ), f"Expected IAM role with URN {random_iam_role.arn} to be present in the response, but it was not found. Found: {urns}."

        assert (
            len(urns) == 1
        ), f"Unexpected URNs found. Expected only {random_iam_role.arn}, but found: {urns}."

    def test_verify_iam_role_by_resource_id_in_explorer(
            self,
            api_v1_client,
            random_iam_role,
            aws_account,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if the Explorer response contains only the IAM role matching the resourceId (role name).

        Given:
            - An IAM role selected randomly from AWS with a known role_name (resourceId).
            - A Lacework Explorer response filtered by:
            - Type: "IDENTITY".
            - Accounts: Specific AWS account ID.
            - ResourceType: "AWS_IAM_ROLE".
            - ResourceId: Role name of the IAM role.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified filters and time period.

        Then:
            - The API should return a 200 status code.
            - The response should only contain the IAM role matching the provided resourceId.
            - All 'resourceId' fields in the response should match the role name of the selected IAM role.


        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_iam_role: A randomly selected IAM role with its attributes.
            aws_account: AWS account details, including account ID.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY")

        # Add account filter
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=aws_account.aws_account_id,
        )

        # Add resource type filter
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AWS_IAM_ROLE"]
        )

        # Add resourceId filter
        query.add_filter(key="resourceId",
                         operator=ComparisonOperator.IS_EQUAL_TO,
                         value=random_iam_role.role_name)

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
        logger.info(f"Response from Explorer API:\n{response.json()}")
        response_json = response.json()

        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        resource_ids = {edge.get("node", {}).get(
            "resourceId") for edge in edges if edge.get("node", {}).get("resourceId")}

        assert resource_ids, f"No resourceIds found in the response. Expected all resourceIds to match {
            random_iam_role.role_name}."

        assert (
            random_iam_role.role_name in resource_ids
        ), f"Expected IAM role with resourceId {random_iam_role.role_name} to be present in the response, but it was not found. Found: {resource_ids}."

        assert (
            len(resource_ids) == 1
        ), f"Unexpected resourceIds found. Expected only {random_iam_role.role_name}, but found: {resource_ids}."
