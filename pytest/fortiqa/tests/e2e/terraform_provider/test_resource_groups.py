import json
import logging

import pytest

from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.data.resource_group import ResourceGroupData
from fortiqa.libs.lw.apiv2.api_client.resource_group.resource_group import ResourceGroup

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("deploy_lacework_tf_module", ["resource_group"], indirect=True)
def test_tf_apply_resource_groups_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify resource groups created using lacework TF provider are returned by LW API V2.

    Given: Applied TF module with 'resource group' resource[s].
    When: Listing existing resource groups using LW API.
    Then: Resource groups deployed by terraform should be found in the list returned by API V2.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    resource_groups = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_resource_groups()
    resp = ResourceGroup(api_v2_client).list_all_resource()
    resource_groups_from_api = json.loads(resp.text)["data"]

    not_found = []
    for resource_group in resource_groups:
        found = False
        for api_resource_group in resource_groups_from_api:
            if resource_group["name"] == api_resource_group["name"]:
                # Lacework API returns resource groups in a different format than Terraform
                # Parse into a common format for comparison
                tf_rg = ResourceGroupData.parse_from_terraform(resource_group)
                api_rg = ResourceGroupData.parse_from_lacework_api(
                    api_resource_group
                )
                if tf_rg == api_rg:
                    found = True
        if not found:
            not_found.append(resource_group)
    assert (
        len(not_found) == 0
    ), f"Alert rules {not_found} were not in API response {resource_groups_from_api}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["resource_group"], indirect=True)
@pytest.mark.parametrize(
    "new_resource_group",
    [
        {"resource_group_name": "NewResourceGroup"},
        {"resource_group_name": "NewSecurityGroup"},
    ],
)
def test_tf_apply_updated_resource_groups_check_apiv2(
    deploy_lacework_tf_module, new_resource_group, api_v2_client
):
    """Verify update in terraform module is found in LW API.

    Given: Applied TF module and modified resource group.
    When: Updating resource group using TF module.
    Then: Updated resource group should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        new_resource_group: new resource group to update in TF module.
        api_v2_client: API V2 client for interacting with the Lacework
    """
    deploy_lacework_tf_module.apply(tf_vars=new_resource_group)

    resource_groups = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_resource_groups()

    resp = ResourceGroup(api_v2_client).list_all_resource()
    resource_groups_from_api = json.loads(resp.text)["data"]

    not_found = []
    change_found_in_tf = False
    for resource_group in resource_groups:
        found = False
        if new_resource_group["resource_group_name"] in json.dumps(resource_group):
            change_found_in_tf = True
        for api_resource_group in resource_groups_from_api:
            if resource_group["name"] == api_resource_group["name"]:
                # Lacework API returns resource groups in a different format than Terraform
                # Parse into a common format for comparison
                tf_rg = ResourceGroupData.parse_from_terraform(resource_group)
                api_rg = ResourceGroupData.parse_from_lacework_api(
                    api_resource_group
                )
                if tf_rg == api_rg:
                    found = True

        if not found:
            not_found.append(resource_group)

    assert len(not_found) == 0, f"Resource groups {not_found} were not in API response {resource_groups_from_api}"
    assert change_found_in_tf, f"Resource group {new_resource_group} not found in TF module"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["resource_group"], indirect=True)
@pytest.mark.parametrize(
    "new_resource_group",
    [
        {"resource_group_name": "NewResourceGroup"},
        {"resource_group_name": "NewSecurityGroup"},
    ],
)
def test_tf_plan_updated_resource_groups(deploy_lacework_tf_module, new_resource_group):
    """Verify update in terraform module is reflected in the plan.

    Given: Applied TF module and modified resource group.
    When: Updating resource group using TF module.
    Then: Updated resource group should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        new_resource_group: new resource group to update in TF module.
    """
    plan = deploy_lacework_tf_module.plan(tf_vars=new_resource_group)
    assert (
        new_resource_group["resource_group_name"] in plan
    ), f"resource group not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["resource_group"], indirect=True)
def test_tf_destory_resource_groups_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify resource groups deleted using lacework TF provider are not returned by LW API.

    Given: Applied TF module with 'resource group' resource[s].
    When: Listing existing resource groups using LW API.
    Then: Resource groups deleted by terraform should not be found in the list returned by API.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    resource_groups = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_resource_groups()
    # Delete the resource group using tf module
    deploy_lacework_tf_module.destroy()
    resp = ResourceGroup(api_v2_client).list_all_resource()
    resource_groups_from_api = json.loads(resp.text)["data"]

    not_found = []
    for resource_group in resource_groups:
        found = False
        for api_resource_group in resource_groups_from_api:
            if resource_group["name"] == api_resource_group["name"]:
                # Lacework API returns resource groups in a different format than Terraform
                # Parse into a common format for comparison
                tf_rg = ResourceGroupData.parse_from_terraform(resource_group)
                api_rg = ResourceGroupData.parse_from_lacework_api(
                    api_resource_group
                )
                if tf_rg == api_rg:
                    found = True
        if found:
            not_found.append(resource_group)
    assert (
        len(not_found) == 0
    ), f"Deleted resource group {not_found} were found in API response {resource_groups_from_api}"


new_group = {
    "name": "production ec2 instances",
    "description": "Resource group for production EC2 instances",
    "resourceType": "AWS",
    "query": {
        "filters": {
            "ec2Filter": {
                "field": "Resource Tag",
                "operation": "STARTS_WITH",
                "values": ["*"],
                "key": "HOST"
            },
            "envFilter": {
                "field": "Region",
                "operation": "EQUALS",
                "values": ["*"],
            }
        },
        "expression": {
            "operator": "AND",
            "children": [
                {
                    "operator": "AND",
                    "filterName": "ec2Filter",
                    "children": []
                },
                {
                    "operator": "AND",
                    "filterName": "envFilter",
                    "children": []
                }
            ]
        }
    },
    "enabled": 1
}
# Same resource group as in the tf config
same_group = {
    "name": "My Resource Group",
    "description": "This groups a subset of AWS resources",
    "resourceType": "AWS",
    "query": {
        "filters": {
            "filter1": {
                "field": "Region",
                "operation": "EQUALS",
                "values": ["us-east-1"]
            },
            "filter2": {
                "field": "Region",
                "operation": "EQUALS",
                "values": ["us-west-2"],
            },
            "filter3": {
                "field": "Account",
                "operation": "EQUALS",
                "values": ["987654321"],
            },
            "filter4": {
                "field": "Account",
                "operation": "EQUALS",
                "values": [
                    "123456789"
                ]
            },
            "filter5": {
                "field": "Region",
                "operation": "EQUALS",
                "values": [
                    "us-central-1"
                ]
            },
        },
        "expression": {
            "operator": "OR",
            "children": [
                {
                    "filterName": "filter1",
                },
                {
                    "filterName": "filter2",
                },
                {
                    "operator": "AND",
                    "children": [
                        {
                            "filterName": "filter5",
                        },
                        {
                            "operator": "OR",
                            "children": [
                                {
                                    "filterName": "filter4",
                                },
                                {
                                    "filterName": "filter3",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }
}


@pytest.mark.parametrize("load_lacework_tf_module", ["resource_group"], indirect=True)
@pytest.mark.parametrize(
    "lw_api_create_delete_resource",
    [
        {"api_client_type": ResourceGroup, "payload": same_group},
        {"api_client_type": ResourceGroup, "payload": new_group},
    ],
    indirect=True,
)
def test_tf_import_resource_groups_created_by_apiv2(
    load_lacework_tf_module, lw_api_create_delete_resource
):
    """Verify if tf module can import resource group created using Lacework API.

    Given: TF module loaded with resource group configs.
    When: Using tf module to import new resource group created using Lacework API.
    Then: Imported resource group should be found in the plan.

    Args:
        load_lacework_tf_module: TF module.
        lw_api_create_delete_resource: creates and deletes resources using Lacework API.
    """
    resource_name = lw_api_create_delete_resource._resource_name
    resource_id = lw_api_create_delete_resource.find_id_by_name(resource_name)
    assert resource_id, f"Resource group not found in API response: {resource_name}"

    load_lacework_tf_module.execute_command(
                    "import", "lacework_resource_group.example", resource_id)
    plan = load_lacework_tf_module.plan()

    if resource_name == same_group.get("name"):
        assert (
            "No changes. Your infrastructure matches the configuration." in plan
        ), f"Changes should not be found in plan: {plan}"
    else:
        assert (resource_name in plan), f"Changes should be found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["resource_group"], indirect=True)
def test_tf_plan_resource_groups_updated_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify when resource group is managed by tf, updates using api are reflected in the plan.

    Given: Applied TF module with 'resource group' resource[s].
    When: Updating resource group using LW API.
    Then: Updated resource group should be found in the plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    resource_groups = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_resource_groups()
    resource_group = resource_groups[0]
    resp = ResourceGroup(api_v2_client).list_all_resource()
    resource_groups_from_api = json.loads(resp.text)["data"]
    resource_group_from_api = None
    # Find the resource group from API response to update
    for api_resource_group in resource_groups_from_api:
        if resource_group["name"] == api_resource_group["name"]:
            resource_group_from_api = api_resource_group
            break
    assert resource_group_from_api, f"Resource group not found in API response: {resource_group}"

    # Initialize the resource group client with the resource group from API
    resource_client = ResourceGroup(api_v2_client, resource_group_from_api)
    # update the name field of the resource group under the same resource group guid
    resp = resource_client.update_resource(
            {"name": "Updated Resource Group name"}
        )
    assert resp.status_code == 200, f"Failed to update resource group: {resp.text}"

    plan = deploy_lacework_tf_module.plan()
    assert (
        "No changes. Your infrastructure matches the configuration." not in plan
    ), f"Changes should be found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["resource_group"], indirect=True)
def test_tf_plan_resource_groups_deleted_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify resource group deleted using Lacework API is found in the terraform plan.

    Given: Lacework API client.
    When: Deleting a resource group using LW API.
    Then: Deleted Resource group should be found in the terrform plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    resource_groups = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_resource_groups()
    resource_group = resource_groups[0]
    resp = ResourceGroup(api_v2_client).list_all_resource()
    resource_groups_from_api = json.loads(resp.text)["data"]
    resource_group_from_api = None
    # Find the resource group from API response to delete
    for api_resource_group in resource_groups_from_api:
        if resource_group["name"] == api_resource_group["name"]:
            resource_group_from_api = api_resource_group
            break
    assert resource_group_from_api, f"Resource group not found in API response: {resource_group}"

    # Initialize the resource group client with the resource group from API
    resource_client = ResourceGroup(api_v2_client, resource_group_from_api)
    # delete the resource group (initialized)
    resp = resource_client.delete_resource()

    plan = deploy_lacework_tf_module.plan()
    assert (
        "Plan: 1 to add" in plan
    ), f"Changes should be found in plan: {plan}"
    assert (
        f"+ name         = \"{resource_group_from_api['name']}\"" in plan
    ), f"Resource group not found in plan: {plan}"
