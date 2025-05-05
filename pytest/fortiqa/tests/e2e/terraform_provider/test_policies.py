import json
import logging

import pytest

from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.lw.apiv2.api_client.policies.policies import Policies
from fortiqa.libs.data.policy import PolicyData

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("deploy_lacework_tf_module", ["policy"], indirect=True)
def test_tf_apply_policies_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify policies created using lacework tf module are returned by LW API.

    Given: Applied TF module with 'policy' resource[s].
    When: Listing existing policies using LW API.
    Then: Policies deployed by terraform should be found in the list returned by API.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    policies = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_policies()
    resp = Policies(api_v2_client).list_all_resource()
    policies_from_api = json.loads(resp.text)["data"]

    for policy in policies:
        if not policy:
            continue
        found = False
        from_tf = PolicyData.from_tf(policy)
        for api_policy in policies_from_api:
            from_api = PolicyData.from_api(api_policy)
            if from_tf.matches(from_api):
                found = True
                break
        assert found, f"Policy {json.dumps(from_tf.__dict__, indent=4)} not found in API response {json.dumps(from_api.__dict__, indent=4)}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["policy"], indirect=True)
@pytest.mark.parametrize(
    "update_policy",
    [
        {"policy_title": "new policy title for test"}
    ],
)
def test_tf_apply_updated_policies_check_apiv2(
        deploy_lacework_tf_module, update_policy, api_v2_client
):
    """Verify update in terraform module is reflected in the plan.

    Given: Applied TF module and modified alert profile.
    When: Updating policy using TF module.
    Then: Updated policy should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        update_policy: new policy details.
        api_v2_client: API V2 client for interacting with the Lacework.
    """
    deploy_lacework_tf_module.apply(tf_vars=update_policy, use_cache=False)

    policies = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_policies()
    resp = Policies(api_v2_client).list_all_resource()
    policies_from_api = json.loads(resp.text)["data"]

    not_found = []
    change_found_in_tf = False
    for policy in policies:
        found = False
        from_tf = PolicyData.from_tf(policy)
        # Check if changed name is found in API response.
        if update_policy["policy_title"] in json.dumps(from_tf.__dict__):
            change_found_in_tf = True
        for api_policy in policies_from_api:
            from_api = PolicyData.from_api(api_policy)
            if from_tf.matches(from_api):
                found = True
        if not found:
            not_found.append(policy)
    assert len(not_found) == 0, f"policy {not_found} were not in API response"
    assert change_found_in_tf, f"new policy {update_policy} not found in TF resource"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["policy"], indirect=True)
@pytest.mark.parametrize(
    "update_policy",
    [
        {"policy_title": "new policy title for test"}
    ],
)
def test_tf_plan_updated_policies(deploy_lacework_tf_module, update_policy):
    """Verify update in terraform module is reflected in the plan.

    Given: Applied TF module and modified policies.
    When: Updating policies using TF module.
    Then: Updated policies should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        update_policy: new resource group to update in TF module.
    """
    plan = deploy_lacework_tf_module.plan(tf_vars=update_policy)
    assert (
        update_policy["policy_title"] in plan
    ), f"New policy not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["policy"], indirect=True)
def test_tf_destory_policies_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify policy deleted using TF module is Not found in LW API.

    Given: Applied TF module with 'policy' resource[s].
    When: Listing existing policies using LW API.
    Then: Policy deleted by terraform should NOT be found in the list returned by API.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    policies = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_policies()
    # Delete the resource group using tf module
    deploy_lacework_tf_module.destroy()
    resp = Policies(api_v2_client).list_all_resource()
    policies_from_api = json.loads(resp.text)["data"]

    for policy in policies:
        found = False
        from_tf = PolicyData.from_tf(policy)
        for api_policy in policies_from_api:
            from_api = PolicyData.from_api(api_policy)
            if from_tf.matches(from_api):
                found = True
                break

        assert not found, f"Policy {json.dumps(from_tf.__dict__, indent=4)} should NOT be found in API response {json.dumps(from_api.__dict__, indent=4)}"


new_policy = {
    "policyType": "Compliance",
    "queryId": "LW_Global_AWS_Config_S3BucketPolicyWithGlobalDeletePermissions",
    "title": "new policy title for test",
    "enabled": True,
    "description": "new policy description for test",
    "remediation": "new policy remediation for test",
    "severity": "low",
    "alertEnabled": False,
}


@pytest.mark.parametrize("load_lacework_tf_module", ["policy"], indirect=True)
@pytest.mark.parametrize(
    "lw_api_create_delete_resource",
    [
        {"api_client_type": Policies, "payload": new_policy},
    ],
    indirect=True,
)
def test_tf_import_policies_created_by_apiv2(
    load_lacework_tf_module, lw_api_create_delete_resource
):
    """Verify if tf module can import policies created using Lacework API.

    Given: TF module loaded with policy configs.
    When: Using tf module to import new policies created using Lacework API.
    Then: Imported policies should be found in the plan.

    Args:
        load_lacework_tf_module: TF module.
        lw_api_create_delete_resource: creates and deletes resources using Lacework API.
    """
    resource_name = lw_api_create_delete_resource._resource_name
    resource_id = lw_api_create_delete_resource.find_id_by_title(resource_name)
    # resource_id = lw_api_create_delete_resource._resource_id
    assert resource_id, "PolicyId not found"

    load_lacework_tf_module.execute_command(
                    "import", "lacework_policy.example", resource_id)
    plan = load_lacework_tf_module.plan()
    # New policy title overrides the existing title in the plan.
    assert (
        f"\"{new_policy['title']}\" ->" in plan
    ), f"Policy name {resource_id} not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["policy"], indirect=True)
def test_tf_plan_policies_updated_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify when policies is managed by tf, updates using lacework api are reflected in tf plan.

    Given: Applied TF module and lacework api client
    When: Updating policies using lacework api
    Then: Updated policies should be found in the plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    policies = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_policies()
    policy = policies[0]

    policy_id = policy["id"]
    updates = {
        "title": "Update_Policy_Name",
    }

    resource_client = Policies(api_v2_client)

    resp = resource_client.update_resource(
        updates, resource_id=policy_id
    )
    assert resp.status_code == 200, f"Failed to update policy: {resp.text}"

    plan = deploy_lacework_tf_module.plan()

    assert "~ update in-place" in plan, f"Update not found in plan: {plan}"
    assert (
        "\"Update_Policy_Name\" ->" in plan
    ), f"updated alert name not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["policy"], indirect=True)
def test_tf_plan_policies_deleted_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify policies deleted using lacework api is not found in the list returned by LW API.

    Given: Lacework api client
    When: Deleting policies using lacework api
    Then: Policies deleted should be reflected in terraform plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    policies = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_policies()
    policy = policies[0]
    alert_profile_id = policy["id"]
    resp = Policies(api_v2_client).delete_resource(alert_profile_id)
    assert resp.status_code == 204, f"Failed to delete policy: {resp.text}"
    # When resource is deleted using LW API,
    # local config will be shown as updates (+create) in the plan.
    plan = deploy_lacework_tf_module.plan()

    assert (
        "+ create" in plan
    ), f"Policy creation not found in plan: {plan}"
