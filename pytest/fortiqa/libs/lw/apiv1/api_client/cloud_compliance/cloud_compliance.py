import logging
import requests
import time
from typing import Any
from fortiqa.libs.helper.date_helper import timestamp_to_iso
logger = logging.getLogger(__name__)


class CloudComplianceV1:
    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._base_url = f"{api_v1_client.url}/card/query"
        self._endpoints = {
            "policy_stats": f"{self._base_url}/CloudCompliance_PolicyStats",
            "policies_by_resource": f"{self._base_url}/CloudCompliance_PoliciesByResource",
            "dashboard_stats": f"{self._base_url}/CloudCompliance_DashboardStats",
            "group_by_assessment": f"{self._base_url}/CloudCompliance_GroupByAssessment",
            "group_by_accounts": f"{self._base_url}/CloudCompliance_GroupByAccounts"
        }

    def get_policy_stats(self, payload: dict) -> requests.Response:
        """Fetch policy-level compliance statistics across all cloud accounts and services.

        Args:
            payload (dict): The request body, typically created with `build_common_payload`.

        Returns:
            requests.Response: The raw HTTP response from the Lacework PolicyStats API.
        """
        return self._user_api.post(url=self._endpoints["policy_stats"], payload=payload)

    def get_policies_by_resource(self, payload: dict) -> requests.Response:
        """Retrieve a list of resources that are compliant or non-compliant with specific policies.

        This endpoint supports filtering by policy ID, compliance status, cloud account, and more.

        Args:
            payload (dict): The request body, typically created with `build_common_payload`.

        Returns:
            requests.Response: The raw HTTP response from the Lacework PoliciesByResource API.
        """
        return self._user_api.post(url=self._endpoints["policies_by_resource"], payload=payload)

    def get_dashboard_stats(self, payload: dict) -> requests.Response:
        """Fetch summary dashboard statistics for cloud compliance.

        Args:
            payload (dict): The request body, typically created with `build_common_payload`.

        Returns:
            requests.Response: The raw HTTP response from the Lacework DashboardStats API.
        """
        return self._user_api.post(url=self._endpoints["dashboard_stats"], payload=payload)

    def get_group_by_assessment(self, payload: dict) -> requests.Response:
        """
        Retrieve compliance details grouped by assessment (framework) across policies.


        Args:
            payload (dict): The request body, typically created with `build_common_payload`.

        Returns:
            requests.Response: The raw HTTP response from the Lacework GroupByAssessment API.
        """
        return self._user_api.post(url=self._endpoints["group_by_assessment"], payload=payload)

    def get_group_by_accounts(self, payload: dict) -> requests.Response:
        """
        Fetch cloud compliance statistics grouped by cloud account.

        Args:
            payload (dict): The request body, typically created with `build_common_payload`.

        Returns:
            requests.Response: The raw HTTP response from the Lacework GroupByAccounts API.
        """
        return self._user_api.post(url=self._endpoints["group_by_accounts"], payload=payload)

    def check_for_policy_update(
        self,
        start_time_range: int,
        end_time_range: int,
        cloud_provider: str,
        provider_ids: list[str],
        expected_assessment_time: int,
        timeout_seconds: int = 60
    ) -> bool:
        """
        Wait for cloud compliance policy updates to be reflected in the Lacework API within the given timeout.

        This method polls the CloudCompliance_PolicyStats endpoint to check whether all returned
        policies have a LAST_EVAL_TIME that falls after the specified expected assessment time.

        Args:
            start_time_range (int): Start of the time window (in epoch ms) used to query policy evaluation times.
            end_time_range (int): End of the time window (in epoch ms) used to query policy evaluation times.
            cloud_provider (str): One of 'AWS', 'Azure', 'GCP', or 'OCI' (case-insensitive).
            provider_ids (list[str]): List of account/subscription/project/compartment IDs to filter by.
            expected_assessment_time (int): Minimum LAST_EVAL_TIME expected in the API response (in epoch ms).
            timeout_seconds (int): Max number of seconds to wait for update (default: 60).

        Returns:
            bool: True if policy update completed within timeout, False otherwise.

        Raises:
            ValueError: If unsupported cloud_provider is passed.
        """
        account_ids, subscription_ids, project_ids, compartment_ids = get_provider_filters(cloud_provider, provider_ids)

        #  Build payload once
        payload = build_common_payload(
            start_time=start_time_range,
            end_time=end_time_range,
            latest=True,
            account_ids=account_ids,
            subscription_ids=subscription_ids,
            project_ids=project_ids,
            compartment_ids=compartment_ids,
            force_include_keys=["AccountIds", "SubscriptionIds", "ProjectIds", "CompartmentIds"]
        )

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            response = self.get_policy_stats(payload)
            if response.status_code == 200:
                records = response.json().get("data", [])
                if all(
                    "LAST_EVAL_TIME" in r and r["LAST_EVAL_TIME"] >= expected_assessment_time
                    for r in records
                ):
                    return True
                else:
                    seen_times = set(
                        r["LAST_EVAL_TIME"]
                        for r in records
                        if "LAST_EVAL_TIME" in r
                    )
                    iso_seen = sorted(timestamp_to_iso(t) for t in seen_times)
                    logger.debug(f"Expected assessment time: {timestamp_to_iso(expected_assessment_time)}")
                    logger.debug(f"Observed LAST_EVAL_TIME values (unique ISO): {iso_seen}")
            elif response.status_code == 204:
                logger.info("No data yet. Retrying in 60 seconds...")
            else:
                logger.warning(f"Unexpected response code {response.status_code}. Retrying...")

            time.sleep(60)

        logger.info("Timeout waiting for policy update.")
        return False


def build_common_payload(
    start_time: int,
    end_time: int,
    latest: bool = True,
    policy_ids: list[str] | None = None,
    account_ids: list[str] | None = None,
    subscription_ids: list[str] | None = None,
    project_ids: list[str] | None = None,
    compartment_ids: list[str] | None = None,
    assessment_guids: list[str] | None = None,
    resource_status: list[str] | None = None,
    resource_groups: list[dict] | None = None,
    force_include_keys: list[str] | None = None,
) -> dict:
    """
    Build a dynamic request payload for Lacework Cloud Compliance API endpoints.

    This function constructs the standard JSON payload format with a `ParamInfo` block
    and optional `ResourceGroups`, used by endpoints such as:

    - CloudCompliance_PoliciesByResource
    - CloudCompliance_PolicyStats
    - CloudCompliance_GroupByAssessment
    - CloudCompliance_GroupByAccounts
    - CloudCompliance_DashboardStats

    Lacework interprets filter values as follows:
      - If a filter (e.g. `ProjectIds`) is **omitted**, Lacework includes all data for that cloud provider.
      - If a filter is present with an empty list (`[]`), Lacework **excludes** that provider entirely.

    Provider-specific filter fields:
      - `account_ids`: AWS account IDs (for AWS resources)
      - `subscription_ids`: Azure subscription IDs
      - `project_ids`: GCP project IDs
      - `compartment_ids`: OCI compartment IDs

      Important:
      - For the `CloudCompliance_PoliciesByResource` endpoint:
        - If `policy_ids` is **omitted or an empty list**, no data is returned.
      - For all other endpoints:
        - Omitting `policy_ids` means "all policies".
        - An empty list means "no policies" (exclude all).

    Args:
        start_time (int): Start of time range in epoch milliseconds.
        end_time (int): End of time range in epoch milliseconds.
        latest (bool): Whether to request the most recent snapshot (default: True).
        policy_ids (list[str] | None): List of policy IDs to filter.
        account_ids (list[str] | None): AWS account IDs.
        subscription_ids (list[str] | None): Azure subscription IDs.
        project_ids (list[str] | None): GCP project IDs.
        compartment_ids (list[str] | None): OCI compartment IDs.
        assessment_guids (list[str] | None): Optional assessment GUIDs.
        resource_status (list[str] | None): Compliance status filter, e.g., ["Compliant"] or ["NonCompliant"].
        resource_groups (list[dict] | None): Optional resource group filters. Defaults to [].
        force_include_keys (list[str] | None): List of key names to force into the payload
            even if the value is an empty list (e.g., to intentionally exclude a provider).

    Returns:
        dict: A structured payload to pass to Lacework Cloud Compliance API.
    """
    force_include_keys = force_include_keys or []

    param_info: dict[str, Any] = {
        "StartTimeRange": start_time,
        "EndTimeRange": end_time,
        "Latest": latest
    }

    def should_include(key, value):
        return value is not None or key in force_include_keys

    if should_include("PolicyIds", policy_ids):
        param_info["PolicyIds"] = policy_ids or []
    if should_include("AccountIds", account_ids):
        param_info["AccountIds"] = account_ids or []
    if should_include("SubscriptionIds", subscription_ids):
        param_info["SubscriptionIds"] = subscription_ids or []
    if should_include("ProjectIds", project_ids):
        param_info["ProjectIds"] = project_ids or []
    if should_include("CompartmentIds", compartment_ids):
        param_info["CompartmentIds"] = compartment_ids or []
    if should_include("ResourceStatus", resource_status):
        param_info["ResourceStatus"] = resource_status or []
    if assessment_guids:
        param_info["AssessmentGuid"] = assessment_guids

    return {
        "ParamInfo": param_info,
        "ResourceGroups": resource_groups or []
    }


def get_provider_filters(cloud_provider: str, provider_ids: list[str]) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Return provider-specific values for account_ids, subscription_ids, project_ids, and compartment_ids.

    Args:
        cloud_provider (str): One of 'aws', 'azure', 'gcp', or 'oci'.
        provider_ids (list[str]): The list of provider-specific IDs.

    Returns:
        Tuple of four lists in this order:
            - account_ids
            - subscription_ids
            - project_ids
            - compartment_ids
    """
    cloud_provider = cloud_provider.strip().lower()

    if cloud_provider == "aws":
        return provider_ids, [], [], []
    elif cloud_provider == "azure":
        return [], provider_ids, [], []
    elif cloud_provider == "gcp":
        return [], [], provider_ids, []
    elif cloud_provider == "oci":
        return [], [], [], provider_ids
    else:
        raise ValueError(f"Unsupported cloud provider: {cloud_provider}")


def get_expected_compliance_by_resource_type(
    modules: dict[str, dict],
    resource_type: str
) -> dict[str, dict[str, list[str]]]:
    """
    Extract expected compliance results for a given resource type from a dictionary of Terraform modules.

    Each value in the dictionary should contain a 'tf' key referencing a TerraformTest instance.
    The function retrieves the `lacework_expected_compliance` output from each module and extracts
    the compliant and non_compliant resources for the specified resource type (e.g., 's3', 'iam-role').

    Args:
        modules (dict[str, dict]): Dictionary where each key is a module name and value contains:
            {
                "tf": <TerraformTest instance>,
                "deployment_time": ...,
                "deployment_timestamp": ...
            }
        resource_type (str): The resource type key to extract compliance data for.

    Returns:
        dict[str, dict[str, list[str]]]: Dictionary mapping policy IDs to their compliant and non_compliant URNs.

    Example:
        result = get_expected_compliance_by_resource_type(e2e_aws_resources, "s3")
        # {
        #   "lacework-global-50": {
        #     "compliant": [...],
        #     "non_compliant": [...]
        #   },
        #   ...
        # }
    """
    result: dict[str, dict[str, list[str]]] = {}

    for module_name, module in modules.items():
        tf_module = module["tf"]
        output = tf_module.output()
        logger.debug(f"\n=== Output for module: {module_name} ===\n")
        for key, value in output.items():
            logger.debug(f"{key} = {value}")
        expected = output.get("lacework_expected_compliance", {})
        resource_data = expected.get(resource_type, {})

        for policy_id, compliance in resource_data.items():
            if policy_id not in result:
                result[policy_id] = {"compliant": [], "non_compliant": []}

            result[policy_id]["compliant"].extend(compliance.get("compliant", []))
            result[policy_id]["non_compliant"].extend(compliance.get("non_compliant", []))

    return result
