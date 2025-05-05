import logging
from fortiqa.libs.lw.apiv1.api_client.cloud_compliance.cloud_compliance import build_common_payload

logger = logging.getLogger(__name__)


class TestCloudComplianceIAMPoliciesV1:

    def test_iam_users_compliant_with_global_42_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_users_by_policy,
        wait_for_cloud_compliance_policy_update_aws,
    ):
        """
        Verify that all Terraform-deployed compliant IAM users for lacework-global-42 are detected in Lacework.

        This policy ensures that there is only one active access key per IAM user.

        A user is considered **compliant** with this policy if:
        - They have **no** access keys or only **one active** access key.

        Given:
            - Terraform output listing compliant IAM users for lacework-global-42.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-42'.

        Then:
            - All expected compliant IAM user URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_users_by_policy: Terraform output listing IAM user URNs by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-42"
        expected_urns = set(
            expected_compliance_iam_users_by_policy.get(policy_id, {}).get("compliant", [])
        )
        assert expected_urns, f"No compliant IAM users defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        payload = build_common_payload(
            start_time=time_range["start_time_range"],
            end_time=time_range["end_time_range"],
            policy_ids=[policy_id],
            resource_status=["Compliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing compliant IAM user URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant IAM users were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_users_non_compliant_with_global_42_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_users_by_policy,
        wait_for_cloud_compliance_policy_update_aws,
    ):
        """
        Verify that all Terraform-deployed non-compliant IAM users for lacework-global-42 are detected in Lacework.

        A user is considered **non-compliant** if:
        - They have **two or more active** access keys.

        Given:
            - Terraform output listing non-compliant IAM users for lacework-global-42.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-42'.

        Then:
            - All expected non-compliant IAM user URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_users_by_policy: Terraform output listing IAM user URNs by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-42"
        expected_urns = set(
            expected_compliance_iam_users_by_policy.get(policy_id, {}).get("non_compliant", [])
        )
        assert expected_urns, f"No non-compliant IAM users defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        payload = build_common_payload(
            start_time=time_range["start_time_range"],
            end_time=time_range["end_time_range"],
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing non-compliant IAM user URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant IAM users were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_users_compliant_with_global_44_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_users_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed compliant IAM users for lacework-global-44 are detected in Lacework.

        This policy ensures IAM users receive permissions **only through groups**, not directly.

        A user is considered **compliant** if:
        - They have **no inline policies**, and
        - They have **no managed policies attached**, regardless of group membership.

        Users without any permissions at all (not in a group, no policies) are also compliant.

        Given:
            - Terraform output listing compliant IAM users for lacework-global-44.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-44'.

        Then:
            - All expected IAM user URNs must appear in the API response with compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_users_by_policy: Fixture returning expected compliant and non-compliant IAM users by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-44"
        expected_urns = set(expected_compliance_iam_users_by_policy[policy_id]["compliant"])
        assert expected_urns, f"No compliant IAM users defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing compliant IAM user URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant IAM users were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_users_non_compliant_with_global_44_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_users_by_policy,
        wait_for_cloud_compliance_policy_update_aws,
    ):
        """
        Verify that all Terraform-deployed non-compliant IAM users for lacework-global-44 are detected in Lacework.

        This policy ensures IAM users receive permissions **only** through IAM groups.

        A user is considered **non-compliant** with this policy if:
        - They have directly attached managed or inline policies.

        Given:
            - Terraform output listing non-compliant IAM users for lacework-global-44.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-44'.

        Then:
            - All expected non-compliant IAM user URNs must appear in the API response.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_users_by_policy: Terraform output listing IAM user URNs by policy ID and compliance status.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-44"
        expected_urns = set(
            expected_compliance_iam_users_by_policy.get(policy_id, {}).get("non_compliant", [])
        )
        assert expected_urns, f"No non-compliant IAM users defined in Terraform output for policy: {policy_id}"

        time_range = wait_for_cloud_compliance_policy_update_aws
        payload = build_common_payload(
            start_time=time_range["start_time_range"],
            end_time=time_range["end_time_range"],
            policy_ids=[policy_id],
            resource_status=["NonCompliant"]
        )

        response = cloud_compliance_v1_client.get_policies_by_resource(payload)
        assert response.status_code == 200, f"Lacework API returned unexpected status code: {response.status_code}"

        actual_urns = {record["URN"] for record in response.json().get("data", [])}
        missing_urns = expected_urns - actual_urns

        if missing_urns:
            logger.error(f"Missing non-compliant IAM user URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant IAM users were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_users_compliant_with_global_45_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_users_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed compliant IAM users for lacework-global-45 are detected in Lacework.

        This policy ensures IAM policies that allow full administrative privileges ("*:*") are not attached to users.

        A user is considered **compliant** if:
        - They are **not directly or indirectly (via group) attached** to any policy that allows `"Action": "*"` and `"Resource": "*"`.

        Given:
            - Terraform output listing compliant IAM users for lacework-global-45.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-45'.

        Then:
            - All expected IAM user URNs must appear in the API response with compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_users_by_policy: Fixture returning expected compliant and non-compliant IAM users by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-45"
        expected_urns = set(expected_compliance_iam_users_by_policy[policy_id]["compliant"])
        assert expected_urns, f"No compliant IAM users defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing compliant IAM user URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant IAM users were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_users_non_compliant_with_global_45_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_users_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed non-compliant IAM users for lacework-global-45 are detected in Lacework.

        This policy ensures IAM policies that allow full administrative privileges ("*:*") are not attached to users.

        A user is considered **non-compliant** if:
        - They are attached to a policy (directly or via group) that includes `"Action": "*"` and `"Resource": "*"`.

        Given:
            - Terraform output listing non-compliant IAM users for lacework-global-45.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-45'.

        Then:
            - All expected IAM user URNs must appear in the API response with non-compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_users_by_policy: Fixture returning expected compliant and non-compliant IAM users by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-45"
        expected_urns = set(expected_compliance_iam_users_by_policy[policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant IAM users defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing non-compliant IAM user URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant IAM users were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_groups_compliant_with_global_485_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_groups_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed compliant IAM groups for lacework-global-485 are detected in Lacework.

        This policy ensures that IAM policies which allow full administrative privileges ("*:*") are not attached to IAM groups.

        A group is considered **non-compliant** if:
        - It is directly attached to a policy that allows `"Action": "*"` and `"Resource": "*"`.

        Given:
            - Terraform output listing compliant IAM groups for lacework-global-485.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-485'.

        Then:
            - All expected IAM group URNs must appear in the API response with compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_groups_by_policy: Fixture returning expected compliant and non-compliant IAM groups by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-485"
        expected_urns = set(expected_compliance_iam_groups_by_policy[policy_id]["compliant"])
        assert expected_urns, f"No compliant IAM groups defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing compliant IAM group URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant IAM groups were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_groups_non_compliant_with_global_485_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_groups_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed non-compliant IAM groups for lacework-global-485 are detected in Lacework.

        This policy ensures that IAM policies which allow full administrative privileges ("*:*") are not attached to IAM groups.

        A group is considered **non-compliant** if:
        - It is directly attached to a policy that allows `"Action": "*"` and `"Resource": "*"`.

        Given:
            - Terraform output listing non-compliant IAM groups for lacework-global-485.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-485'.

        Then:
            - All expected IAM group URNs must appear in the API response with non-compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_groups_by_policy: Fixture returning expected compliant and non-compliant IAM groups by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-485"
        expected_urns = set(expected_compliance_iam_groups_by_policy[policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant IAM groups defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing non-compliant IAM group URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant IAM groups were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_roles_compliant_with_global_486_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_roles_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed compliant IAM roles for lacework-global-486 are detected in Lacework.

        This policy ensures that IAM policies which allow full administrative privileges ("*:*") are not attached to IAM roles.

        A role is considered **non-compliant** if:
        - It is directly attached to a policy that allows `"Action": "*"` and `"Resource": "*"`.

        Given:
            - Terraform output listing compliant IAM roles for lacework-global-486.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-486'.

        Then:
            - All expected IAM role URNs must appear in the API response with compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_roles_by_policy: Fixture returning expected compliant and non-compliant IAM roles by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-486"
        expected_urns = set(expected_compliance_iam_roles_by_policy[policy_id]["compliant"])
        assert expected_urns, f"No compliant IAM roles defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing compliant IAM role URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected compliant IAM roles were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )

    def test_iam_roles_non_compliant_with_global_486_are_detected(
        self,
        cloud_compliance_v1_client,
        expected_compliance_iam_roles_by_policy,
        wait_for_cloud_compliance_policy_update_aws
    ):
        """
        Verify that all Terraform-deployed non-compliant IAM roles for lacework-global-486 are detected in Lacework.

        This policy ensures that IAM policies which allow full administrative privileges ("*:*") are not attached to IAM roles.

        A role is considered **non-compliant** if:
        - It is directly attached to a policy that allows `"Action": "*"` and `"Resource": "*"`.

        Given:
            - Terraform output listing non-compliant IAM roles for lacework-global-486.
            - Daily collection and policy assessment has already completed (via fixture).

        When:
            - Querying Lacework's CloudCompliance_PoliciesByResource API with policy ID 'lacework-global-486'.

        Then:
            - All expected IAM role URNs must appear in the API response with non-compliant status.

        Args:
            cloud_compliance_v1_client: API client for querying Lacework Cloud Compliance.
            expected_compliance_iam_roles_by_policy: Fixture returning expected compliant and non-compliant IAM roles by policy.
            wait_for_cloud_compliance_policy_update_aws: Fixture that ensures policy assessments have completed and provides start and end time range for the API payload.
        """
        policy_id = "lacework-global-486"
        expected_urns = set(expected_compliance_iam_roles_by_policy[policy_id]["non_compliant"])
        assert expected_urns, f"No non-compliant IAM roles defined in Terraform output for policy: {policy_id}"

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
            logger.error(f"Missing non-compliant IAM role URNs for policy {policy_id}:\n" + "\n".join(f"  - {urn}" for urn in missing_urns))

        assert not missing_urns, (
            f"The following expected non-compliant IAM roles were not returned by the API for policy {policy_id}:\n" +
            "\n".join(missing_urns)
        )
