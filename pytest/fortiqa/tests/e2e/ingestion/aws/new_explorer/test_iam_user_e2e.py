import logging
import pytest
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.new_graphql_helper import NewGraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.new_graph_ql.new_graph_ql import NewGraphQL

logger = logging.getLogger(__name__)


class TestExplorerIAMUsers:
    @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/PSP-3090')
    def test_verify_find_all_iam_users_in_explorer_vs_aws(
            self,
            api_v1_client,
            aws_account,
            all_aws_iam_users,
            ingestion_tag,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if all IAM Users retrieved from AWS are present in the Explorer's response, optionally filtered by ingestion tags.

        Given:
            - A list of IAM Users retrieved from AWS.
            - A Lacework Explorer response containing resource details filtered by the AWS account and resource type.
            - An optional ingestion tag to filter resources in the Explorer's response.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AWS_IAM_USER' for the specified account,
              optionally filtered by tags.

        Then:
            - All IAM Users retrieved from AWS should have their ARNs present as URNs in the Explorer's response.
            - No extra URNs should be present in the Explorer's response that are not part of the AWS IAM Users.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            aws_account: AWS account details.
            all_aws_iam_users: A list of IAM Users retrieved from AWS.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tag in the Explorer's query.
                        If None, no filtering is applied in the query.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        # Build URNs for all IAM Users
        aws_iam_user_urns = {user.arn for user in all_aws_iam_users}

        graph_api = NewGraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY_RESOURCE")
        accounts = query.add_filter(key="account")
        accounts.add_subfilter(
            key="Id",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=aws_account.aws_account_id,
        )
        query.add_filter(
            key="type", operator=ComparisonOperator.IS_IN, value=["AWS_IAM_USER"])
        tags = ingestion_tag
        if tags:
            tag_payload = [{"key": key, "value": {"eq": value}}
                           for key, value in tags.items()]
            query.add_filter(key="resourceTags",
                             operator=ComparisonOperator.IS_ANY_OF,
                             value=tag_payload)

        generated_payload = NewGraphQLHelper().generate_payload(
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
        missing_urns = aws_iam_user_urns - explorer_urns
        assert not missing_urns, f"Missing URNs in Explorer response: {
            missing_urns}"

        # Verify Explorer does not contain unexpected URNs
        unexpected_urns = explorer_urns - aws_iam_user_urns
        assert not unexpected_urns, f"Unexpected URNs in Explorer response: {
            unexpected_urns}"

    def test_verify_iam_user_by_urn_in_explorer(
            self,
            api_v1_client,
            random_iam_user,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if the IAM User is present in the Explorer by searching with the URN.

        Given:
            - An IAM User selected randomly from AWS with a known URN (ARN).
            - A Lacework Explorer response filtered by:
            - Type: "IDENTITY_RESOURCE".
            - URN: The ARN of the IAM User.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture providing the latest Explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API using the specified URN and type within the latest time period.

        Then:
            - All 'urn' fields in the response should match the ARN of the selected IAM User.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_iam_user: A randomly selected IAM User with its attributes, including its ARN.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        graph_api = NewGraphQL(api_v1_client)
        query = GraphQLFilter(type="IDENTITY_RESOURCE")

        # Add URN filter
        query.add_filter(key="urn",
                         operator=ComparisonOperator.IS_EQUAL_TO,
                         value=random_iam_user.arn)

        generated_payload = NewGraphQLHelper().generate_payload(
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
            random_iam_user.arn}."

        assert (
            random_iam_user.arn in urns
        ), f"Expected IAM User with URN {random_iam_user.arn} to be present in the response, but it was not found. Found: {urns}."

        assert (
            len(urns) == 1
        ), f"Unexpected URNs found. Expected only {random_iam_user.arn}, but found: {urns}."
