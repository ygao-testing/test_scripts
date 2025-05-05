import logging
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL


logger = logging.getLogger(__name__)


class TestExplorerRDS:
    def test_verify_find_all_rds_db_instances_in_explorer_vs_aws(
            self,
            api_v1_client,
            aws_account,
            all_aws_rds_db_instances_region,
            ingestion_tag,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """Verify if all RDS DB Instances retrieved from AWS are present in the Explorer's response, optionally filtered by ingestion tags,

        Given:
            - A list of RDS DB Instances retrieved from AWS.
            - A Lacework Explorer response containing resource details filtered by the AWS account and resource type.
            - An optional ingestion tag to filter resources in the Explorer's response.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AWS_RDS_DB' for the specified account,
            optionally filtered by tags.

        Then:
            - All RDS DB Instances retrieved from AWS should have their ARNs present as URNs in the Explorer's response.
            - No extra URNs should be present in the Explorer's response that are not part of the AWS RDS DB Instances.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            aws_account: AWS account details.
            all_aws_rds_db_instances_region: A list of RDS DB Instances retrieved from AWS.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tag in the Explorer's query.
                        If None, no filtering is applied in the query.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws
        aws_rds_instance_arns = {
            instance.db_instance_arn for instance in all_aws_rds_db_instances_region}

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="DATA")
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=aws_account.aws_account_id,
        )
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AWS_RDS_DB"])
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
        assert "errors" not in response.json(), f"Expected no errors in response, but got {
            response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract URNs from Explorer's response
        explorer_urns = {
            edge["node"]["urn"]
            for edge in response_json["data"]["resources"]["edges"]
        }

        # Verify all ARNs from AWS are present in Explorer response
        missing_arns = aws_rds_instance_arns - explorer_urns
        assert not missing_arns, f"Missing ARNs in Explorer response: {
            missing_arns}"

        # Verify Explorer does not contain unexpected URNs
        unexpected_urns = explorer_urns - aws_rds_instance_arns
        assert not unexpected_urns, f"Unexpected URNs in Explorer response: {
            unexpected_urns}"

    def test_verify_rds_by_urn(
            self,
            api_v1_client,
            random_rds_db_instance,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """Verify if the RDS DB Instance is present in the Explorer by searching with the URN.

        Given:
            - A randomly selected RDS DB Instance with a known URN (ARN).
            - A GraphQL query targeting the specified URN.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - The Explorer API is queried using the specified URN within the latest time period.

        Then:
            - The API should return a 200 status code.
            - The 'urn' field in the response should match the URN of the selected RDS DB Instance.

        Args:
            api_v1_client: Client for interacting with the Lacework API v1.
            aws_account: AWS account details, including account ID.
            random_rds_db_instance: A randomly selected RDS DB Instance with its attributes.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                  Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                  and providing the latest explorer update time period in ISO 8601 format.
        """

        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws
        db_instance_arn = random_rds_db_instance.db_instance_arn
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='DATA')
        query.add_filter(key="urn",
                         operator=ComparisonOperator.IS_EQUAL_TO,
                         value=db_instance_arn)
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=latest_update_period["startTime"], end_time_string=latest_update_period["endTime"])
        response = graph_api.exec_query(generated_payload)
        assert response.status_code == 200, f"Expected to get status code 200 from GraphQL API, but got err: {
            response.text}"
        assert "errors" not in response.json(), f"Expect no error returned, but got {
            response.json()['errors'][0]['message']}"
        logger.info(f"response from explorer:\n {response.json()}")
        response_json = response.json()
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        found = any(edge["node"]["urn"] == db_instance_arn for edge in edges)
        assert found, f"Expected rds db instance with arn {
            db_instance_arn} to be present in the response, but it was not found."
