import logging
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL


logger = logging.getLogger(__name__)


class TestExplorerS3:
    def test_verify_find_all_s3_buckets_in_explorer_vs_aws(
            self,
            api_v1_client,
            aws_account,
            all_aws_s3_bucket,
            ingestion_tag,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if all S3 buckets retrieved from AWS are present in the Explorer's response, optionally filtered by ingestion tags.

        Given:
            - A list of S3 buckets retrieved from AWS.
            - A Lacework Explorer response containing resource details filtered by the AWS account and resource type.
            - An optional ingestion tag to filter resources in the Explorer's response.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - A query is executed in the Lacework Explorer API to retrieve resources of type 'AWS_S3_BUCKET' for the specified account,
            optionally filtered by tags.

        Then:
            - All S3 buckets retrieved from AWS should have their URNs present in the Explorer's response.
            - No extra URNs should be present in the Explorer's response that are not part of the AWS S3 buckets.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            aws_account: AWS account details.
            all_aws_s3_bucket: A list of S3 buckets retrieved from AWS.
            ingestion_tag: A dictionary containing key-value pairs for filtering resources by tag in the Explorer's query.
                        If None, no filtering is applied in the query.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        # Build URNs for all S3 buckets
        aws_s3_bucket_urns = {
            f"arn:aws:s3:::{bucket.name}" for bucket in all_aws_s3_bucket
        }

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="DATA")
        accounts = query.add_filter(key="accounts")
        accounts.add_subfilter(
            key="accountId",
            operator=ComparisonOperator.IS_EQUAL_TO,
            value=aws_account.aws_account_id,
        )
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AWS_S3_BUCKET"])
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
        logger.debug(f"response: \n{response.json()} ")
        assert "errors" not in response.json(), f"Expected no errors in response, but got {
            response.json()['errors'][0]['message']}."
        response_json = response.json()

        # Extract URNs from Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        explorer_urns = {edge.get("node", {}).get("urn")
                         for edge in edges if edge.get("node", {}).get("urn")}

        # Verify all URNs from AWS are present in Explorer response
        missing_urns = aws_s3_bucket_urns - explorer_urns
        assert not missing_urns, f"Missing URNs in Explorer response: {
            missing_urns}"

        # Verify Explorer does not contain unexpected URNs
        unexpected_urns = explorer_urns - aws_s3_bucket_urns
        assert not unexpected_urns, f"Unexpected URNs in Explorer response: {
            unexpected_urns}"

    def test_verify_s3_bucket_by_urn_in_explorer(
            self,
            api_v1_client,
            random_s3_bucket,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if the S3 bucket is present in the Explorer by searching with the URN.

        Given:
            - A randomly selected S3 bucket with a known name.
            - The S3 bucket's URN constructed as an ARN.
            - A GraphQL query targeting the specified URN and resource type 'AWS_S3_BUCKET'.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - The Explorer API is queried using the constructed URN and resource type within the latest time period.

        Then:
            - The API should return a 200 status code.
            - The 'urn' field in the response should match the URN of the selected S3 bucket.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_s3_bucket: A randomly selected S3 bucket with its attributes.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """

        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        # Build the URN (ARN) for the S3 bucket
        s3_bucket_urn = f"arn:aws:s3:::{random_s3_bucket.name}"

        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="DATA")

        # Add resource type filter
        query.add_filter(
            key="resourceType", operator=ComparisonOperator.IS_IN, value=["AWS_S3_BUCKET"]
        )

        # Add URN filter
        query.add_filter(key="urn",
                         operator=ComparisonOperator.IS_EQUAL_TO,
                         value=s3_bucket_urn)

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
        logger.info(f"Response from Explorer API:\n{response.json()}")
        response_json = response.json()

        # Verify URN is present in Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])
        explorer_urns = {edge.get("node", {}).get("urn")
                         for edge in edges if edge.get("node", {}).get("urn")}
        assert explorer_urns, f"No URNs found in the response. Expected {
            s3_bucket_urn}."
        assert (
            s3_bucket_urn in explorer_urns
        ), f"Expected S3 bucket with URN {s3_bucket_urn} to be present in the response, but it was not found. Found: {explorer_urns}."

        assert (
            len(explorer_urns) == 1
        ), f"Unexpected URNs found. Expected only {s3_bucket_urn}, but found: {explorer_urns}."

    def test_verify_s3_bucket_by_resource_id_in_explorer(
            self,
            api_v1_client,
            random_s3_bucket,
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify if the S3 bucket is present in the Explorer by searching with the resourceId.

        Given:
            - A randomly selected S3 bucket with a known name.
            - The S3 bucket name as S3 bucket's resourceId.
            - A GraphQL query targeting the specified resourceId.
            - The 'wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws' fixture to get the latest explorer update time period.

        When:
            - The Explorer API is queried using the constructed resourceId within the latest time period.

        Then:
            - The API should return a 200 status code.
            - The 'resourceId' field in the response should match the resourceId of the selected S3 bucket.

        Args:
            api_v1_client: API client for interacting with Lacework's API.
            random_s3_bucket: A randomly selected S3 bucket with its attributes.
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws:
                Fixture ensuring Explorer's latest update timestamps are updated post daily ingestion completion,
                and providing the latest explorer update time period in ISO 8601 format.
        """
        latest_update_period = wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws

        # retrive s3 bucket name as resourceId
        s3_bucket_resource_id = random_s3_bucket.name
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type="DATA")
        # Add resourceId filter
        query.add_filter(key="resourceId",
                         operator=ComparisonOperator.IS_EQUAL_TO,
                         value=s3_bucket_resource_id)

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
        logger.info(f"Response from Explorer API:\n{response.json()}")
        response_json = response.json()
        # Verify resourceId is present in Explorer's response
        edges = response_json.get("data", {}).get(
            "resources", {}).get("edges", [])

        explorer_resource_ids = {edge.get("node", {}).get(
            "resourceId") for edge in edges if edge.get("node", {}).get("resourceId")}

        assert explorer_resource_ids, f"No resourceIds found in the response. Expected {
            s3_bucket_resource_id}."

        assert (
            s3_bucket_resource_id in explorer_resource_ids
        ), f"Expected resourceId {s3_bucket_resource_id} to be present, but it was not found. Found: {explorer_resource_ids}."

        assert (
            len(explorer_resource_ids) == 1
        ), f"Unexpected resourceIds found. Expected only {s3_bucket_resource_id}, but found: {explorer_resource_ids}."
