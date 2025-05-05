
import logging
from fortiqa.libs.lw.apiv1.api_client.cloud_compliance.cloud_compliance import build_common_payload


logger = logging.getLogger(__name__)


class TestCloudComplianceS3PoliciesV1:

    def test_s3_buckets_non_compliant_with_global_50_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-50 are detected in Lacework.

        This policy ensures that S3 buckets are configured to block all public access using the Block Public Access (BPA) settings.

        A bucket is considered **non-compliant** with this policy if:
        - The Block Public Access setting 'RestrictPublicBuckets' is **not enabled** either at the bucket level or account level.

        If 'RestrictPublicBuckets' is enabled, the bucket is considered compliant regardless of its bucket policy.

        Given:
            - Terraform output listing non-compliant S3 buckets for lacework-global-50.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-50'.

        Then:
            - All expected S3 URNs must appear in the API response with non-compliant status.

        Args:
            cloud_compliance_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-50"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        # UI-style payload without provider filtering
        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_compliant_with_global_50_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed compliant S3 buckets for lacework-global-50 are detected in Lacework.

        This policy ensures that S3 buckets are configured to block all public access using the Block Public Access (BPA) settings.

        A bucket is considered **non-compliant** with this policy if:
        - The Block Public Access setting 'RestrictPublicBuckets' is **not enabled** either at the bucket level or account level.

        If 'RestrictPublicBuckets' is enabled, the bucket is considered compliant regardless of its bucket policy.

        Given:
            - Terraform output listing compliant S3 buckets for lacework-global-50.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-50'.

        Then:
            - All expected S3 URNs must appear in the API response with compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-50"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["compliant"])
        assert expected_urns, f"No compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        # UI-style payload without provider filtering
        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected **compliant** S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_compliant_with_global_72_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed compliant S3 buckets for lacework-global-72 are detected in Lacework.
        This policy enforces that all S3 buckets must have encryption-at-rest enabled.

        Note:
            - As of 2023, AWS S3 enables encryption-at-rest by default using SSE-S3 (AES-256).
            - Encryption-at-rest cannot be disabled, so all newly created S3 buckets are compliant by default.
            - This test is expected to always pass unless explicitly overridden in older environments


        Given:
            - Terraform output listing compliant S3 buckets for lacework-global-72.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-72'.

        Then:
            - All expected compliant S3 URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-72"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["compliant"])
        assert expected_urns, f"No compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected **compliant** S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_compliant_with_global_73_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed compliant S3 buckets for lacework-global-73 are detected in Lacework.

        This policy enforces that S3 bucket policies must explicitly deny unencrypted (HTTP) requests using a
        policy condition on 'aws:SecureTransport'.

        A bucket is considered compliant if:
        - Its bucket policy includes a statement with `"Effect": "Deny"` and condition:
            `"Bool": { "aws:SecureTransport": "false" }`.

        Given:
            - Terraform output listing compliant S3 buckets for lacework-global-73.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-73'.

        Then:
            - All expected compliant S3 URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-73"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["compliant"])
        assert expected_urns, f"No compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_non_compliant_with_global_73_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-73 are detected in Lacework.

        This policy enforces that S3 bucket policies must explicitly deny unencrypted (HTTP) requests using a
        policy condition on 'aws:SecureTransport'.

        A bucket is considered compliant if:
        - Its bucket policy includes a statement with `"Effect": "Deny"` and condition:
            `"Bool": { "aws:SecureTransport": "false" }`.

        Given:
            - Terraform output listing non-compliant S3 buckets for lacework-global-73.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-73'.

        Then:
            - All expected non-compliant S3 URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-73"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing non-compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_compliant_with_global_97_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed compliant S3 buckets for lacework-global-97 are detected in Lacework.

        This policy enforces that S3 bucket versioning must be enabled to preserve, retrieve, and restore every version of every object stored.

        A bucket is considered compliant if:
        - Versioning is explicitly enabled via the S3 bucket configuration.

        Given:
            - Terraform output listing compliant S3 buckets for lacework-global-97.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-97'.

        Then:
            - All expected compliant S3 URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-97"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["compliant"])
        assert expected_urns, f"No compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_non_compliant_with_global_97_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-97 are detected in Lacework.

        This policy enforces that S3 bucket versioning must be enabled to preserve, retrieve, and restore every version of every object stored.

        A bucket is considered compliant if:
        - Versioning is explicitly enabled via the S3 bucket configuration.

        Given:
            - Terraform output listing non-compliant S3 buckets for lacework-global-97.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-97' and NonCompliant status.

        Then:
            - All expected S3 URNs must appear in the API response as non-compliant.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-97"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing non-compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_compliant_with_global_98_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-98 are detected in Lacework.

        Ensure the attached S3 bucket policy does not grant global 'Get' permission

        This policy ensures that S3 bucket policies do not grant global 'Get' permissions ('s3:Get*') to all users,
        and that the Block Public Access setting 'RestrictPublicBuckets' is enabled.

        A bucket is considered **non-compliant** with this policy if **both** of the following conditions are met:
        - It has a bucket policy allowing public 'Get' actions ( 's3:Get*') with `Principal = "*"` or `{"AWS": "*"}`.
        - AND the Block Public Access setting 'RestrictPublicBuckets' is **not enabled**.

        If either condition is not met, the bucket is considered compliant.

        Given:
            - Terraform output listing compliant S3 buckets for lacework-global-98.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-98' and Compliant status.

        Then:
            - All expected S3 URNs must appear in the API response as compliant.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-98"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["compliant"])
        assert expected_urns, f"No compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_non_compliant_with_global_98_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-98 are detected in Lacework.

        Ensure the attached S3 bucket policy does not grant global 'Get' permission

        This policy ensures that S3 bucket policies do not grant global 'Get' permissions ('s3:Get*') to all users,
        and that the Block Public Access setting 'RestrictPublicBuckets' is enabled.

        A bucket is considered **non-compliant** with this policy if **both** of the following conditions are met:
        - It has a bucket policy allowing public 'Get' actions ( 's3:Get*') with `Principal = "*"` or `{"AWS": "*"}`.
        - AND the Block Public Access setting 'RestrictPublicBuckets' is **not enabled**.

        If either condition is not met, the bucket is considered compliant.


        Given:
            - Terraform output listing non-compliant S3 buckets for lacework-global-98.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-98' and NonCompliant status.

        Then:
            - All expected S3 URNs must appear in the API response as non-compliant.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-98"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing non-compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_compliant_with_global_100_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed compliant S3 buckets for lacework-global-100 are detected in Lacework.

        Ensure the attached S3 bucket policy does not grant global 'List' permission

        This policy ensures that S3 bucket policies do not grant global 'List' permissions ('s3:List*') to all users,
        and that the Block Public Access setting 'RestrictPublicBuckets' is enabled.

        A bucket is considered **non-compliant** with this policy if **both** of the following conditions are met:
        - It has a bucket policy allowing public 'List' actions ('s3:List*') with `Principal = "*"` or `{"AWS": "*"}`.
        - AND the Block Public Access setting 'RestrictPublicBuckets' is **not enabled**.

        If either condition is not met, the bucket is considered compliant.

        Given:
            - Terraform output listing compliant S3 buckets for lacework-global-100.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-100' and Compliant status.

        Then:
            - All expected S3 URNs must appear in the API response as compliant.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-100"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["compliant"])
        assert expected_urns, f"No compliant S3 buckets defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]

        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_non_compliant_with_global_100_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-100 are detected in Lacework.

        Ensure the attached S3 bucket policy does not grant global 'List' permission

        This policy ensures that S3 bucket policies do not grant global 'List' permissions ( 's3:List*') to all users,
        and that the Block Public Access setting 'RestrictPublicBuckets' is enabled.

        A bucket is considered **non-compliant** with this policy if **both** of the following conditions are met:
        - It has a bucket policy allowing public 'List' actions ('s3:List*') with `Principal = "*"` or `{"AWS": "*"}`.
        - AND the Block Public Access setting 'RestrictPublicBuckets' is **not enabled**.

        If either condition is not met, the bucket is considered compliant.
        Given:
            - Terraform output listing non-compliant S3 buckets for lacework-global-100.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-100' and NonCompliant status.

        Then:
            - All expected S3 URNs must appear in the API response as non-compliant.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-100"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant S3 buckets defined in Terraform output for policy: {policy_id}"
        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]
        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"
        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns
        if missing_urns:
            logger.error(f"Missing non-compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_s3_buckets_non_compliant_with_global_140_are_detected(
        self,
        cloud_compliance_v1_client,
        e2e_aws_resources,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """Verify that all Terraform-deployed non-compliant S3 buckets for lacework-global-140 are detected in Lacework.

        This policy ensures that no S3 bucket policy grants permission to everyone without enabling 'RestrictPublicBuckets'.

        Given:
            - Terraform output listing non-compliant S3 buckets for lacework-global-140.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-140' and NonCompliant status.

        Then:
            - All expected S3 URNs must appear in the API response as non-compliant.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            e2e_aws_resources: Terraform output with S3 bucket names organized by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-140"
        tf_output = e2e_aws_resources["inventory"]["tf"].output()
        expected_urns = set(tf_output["lacework_expected_compliance"]["s3"][policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant S3 buckets defined in Terraform output for policy: {policy_id}"
        time_range = wait_for_cloud_compliance_policy_update_aws
        start_time = time_range["start_time_range"]
        end_time = time_range["end_time_range"]
        payload = build_common_payload(
            start_time=start_time,
            end_time=end_time,
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns
        if missing_urns:
            logger.error(f"Missing non-compliant S3 URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))
        assert not missing_urns, (
            f"The following expected non-compliant S3 buckets were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )
