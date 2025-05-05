import json
import logging

import pytest

from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.lw.apiv2.api_client.alert_rules.alert_rules import AlertRules
from fortiqa.libs.lw.apiv1.api_client.alert_rules.alert_rules import AlertRules as AlertRulesV1
from fortiqa.libs.data.alert_rules import AlertRuleData

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
def test_tf_apply_alert_rules_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify alert rules applied using the lacework TF provider are returned by LW API V2.

    Given: Applied TF module with 'lacework_alert_rules' resource[s].
    When: Listing existing alert rules using LW API.
    Then: Alert rules deployed by terraform should be found in the list returned by API V2.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    resp = AlertRules(api_v2_client).list_all_resource()
    alert_rules_from_api = json.loads(resp.text)["data"]

    not_found = []
    for alert_rule in alert_rules:
        found = False
        from_tf = AlertRuleData.from_tf(alert_rule)
        for api_alert_rule in alert_rules_from_api:
            from_api = AlertRuleData.from_api(api_alert_rule)
            if from_tf.match(from_api):
                found = True
        if not found:
            not_found.append(alert_rule)
    assert len(not_found) == 0, f"Alert rules {not_found} were not in API response"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
@pytest.mark.parametrize(
    "new_rules",
    [
        {"alert_rule_name": "CustomViolation"},
        {"alert_rule_name": "SecurityAlert"},
    ],
)
def test_tf_apply_updated_alert_rules_check_apiv2(
    deploy_lacework_tf_module, new_rules, api_v2_client
):
    """Verify update in terraform module is reflected in the plan.

    Given: Applied TF module and modified alert rule.
    When: Updating alert rule using TF module.
    Then: Updated alert rule should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        new_rules: new alert rule details.
        api_v2_client: API V2 client for interacting with the Lacework.
    """
    deploy_lacework_tf_module.apply(tf_vars=new_rules, use_cache=False)

    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    resp = AlertRules(api_v2_client).list_all_resource()
    alert_rules_from_api = json.loads(resp.text)["data"]

    not_found = []
    change_found_in_tf = False
    for alert_rule in alert_rules:
        found = False
        from_tf = AlertRuleData.from_tf(alert_rule)
        # Check if changed name is found in API response.
        if new_rules["alert_rule_name"] in json.dumps(from_tf.__dict__):
            change_found_in_tf = True
        for api_alert_rule in alert_rules_from_api:
            if from_tf.match(AlertRuleData.from_api(api_alert_rule)):
                found = True
        if not found:
            not_found.append(alert_rule)
    assert len(not_found) == 0, f"Alert rules {not_found} were not in API response"
    assert change_found_in_tf, f"Alert rule {new_rules} not found in TF resource"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
@pytest.mark.parametrize(
    "new_rules",
    [
        {"alert_rule_name": "newalertrule"},
        {"alert_rule_name": "securityrule"},
    ],
)
def test_tf_plan_updated_alert_rules(deploy_lacework_tf_module, new_rules):
    """Verify update in terraform module is reflected in the plan.

    Given: Applied TF module and modified alert rule.
    When: Updating alert rule using TF module.
    Then: Updated alert rule should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        new_rules: new alert rule details.
    """
    # Passing new alert rule using tf_vars,
    # Simulating resource update using tf module
    plan = deploy_lacework_tf_module.plan(tf_vars=new_rules)
    assert (
        new_rules["alert_rule_name"] in plan
    ), f"alert rule not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
def test_tf_destory_alert_rules_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify alert rules deleted using lacework_alert_rules
       of the lacework TF provider are not found in the list returned by LW API.

    Given: Applied TF module with 'lacework_alert_rules' resource[s].
    When: Deleting alert rules using TF module.
    Then: Alert rules deployed by terraform should not be found in the list returned by API.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    deploy_lacework_tf_module.destroy()
    resp = AlertRules(api_v2_client).list_all_resource()
    alert_rules_from_api = json.loads(resp.text)["data"]
    found_rule = []
    for alert_rule in alert_rules:
        found = False
        from_tf = AlertRuleData.from_tf(alert_rule)
        for api_alert_rule in alert_rules_from_api:
            if from_tf.match(AlertRuleData.from_api(api_alert_rule)):
                found = True
        if found:
            found_rule.append(alert_rule)
    assert (
        len(found_rule) == 0
    ), f"Alert rules {found_rule} were found in API response"


new_lw_alert_rule = {
        "filters": {
            "name": "FortiQA Test Alert Rule",
            "description": "Automation test alert rule",
            "enabled": 1,
            "resourceGroups": [],
            "severity": [
                1
            ],
            "eventCategory": [
                "Compliance"
            ],
            "category": [
                "Policy"
            ],
            "source": [
                "AWS"
            ],
            "subCategory": [
                "Compliance"
            ]
        },
        "intgGuidList": [
            "SYSTEME2_7794AF3EBA2D0D28CC5403A91C4CF2C89438B17648BB662"
        ],
        "type": "Event"
    }


@pytest.mark.parametrize("load_lacework_tf_module", ["alert_rule"], indirect=True)
@pytest.mark.parametrize(
    "lw_api_create_delete_resource",
    [{"api_client_type": AlertRules, "payload": new_lw_alert_rule}],
    indirect=True
)
def test_tf_import_alert_rules_created_by_apiv2(load_lacework_tf_module, lw_api_create_delete_resource):
    """Verify alert rule created using lacework api can be imported in terraform.

    Given: TF module loaded with alert rule configuration.
    When: Importing alert rule created using lacework api.
    Then: Alert rule created should be found in terraform plan.

    Args:
        load_lacework_tf_module: loads given TF module.
        lw_api_create_delete_resource: creates alert rule using lacework api.
    """
    # the resource name is used as the id for alert rule from API side.
    resource_name = lw_api_create_delete_resource._resource_name
    resource_id = lw_api_create_delete_resource.find_id_by_name(resource_name)
    assert resource_id, f"Failed to find resource id for {resource_id}"

    load_lacework_tf_module.execute_command(
        "import", "lacework_alert_rule.example", resource_id)
    # tf imports the resource and plan compares the imported resource against existing configs.
    # so existing config will be shown as updates.
    plan = load_lacework_tf_module.plan()
    assert resource_id in plan, (
        f"Expected resource ID '{resource_id}' to be found in the terraform plan, "
        f"indicating that the alert rule created by the API was successfully imported. "
        f"Plan output: {plan}"
    )


new_lw_alert_rule_v1 = {
    "TYPE": "EVENT",
    "FILTERS": {
        "name": "test add alert rule",
        "description": "test add alert rule using v1 api",
        "enabled": 1,
        "eventCategory": [
            "Kubernetes Activity"
        ],
        "category": [
            "Policy"
        ],
        "source": [],
        "severity": [
            2,
            1,
            3
        ],
        "resourceGroups": [
            "LACEWORK_RESOURCE_GROUP_ALL_AWS"
        ]
    },
    "INTG_GUID_LIST": [
        "SYSTEME2_2617F60CF156D86B8FE8473A4B6496064AF35F563AF6F47"
    ]
}


@pytest.mark.parametrize("load_lacework_tf_module", ["alert_rule"], indirect=True)
@pytest.mark.parametrize(
    "lw_apiv1_resource",
    [{"api_client_type": AlertRulesV1, "payload": new_lw_alert_rule_v1}],
    indirect=True
)
def test_tf_import_alert_rules_created_by_apiv1(load_lacework_tf_module, lw_apiv1_resource):
    """Verify alert rule created using lacework api can be imported in terraform.

    Given: TF module loaded with alert rule configuration.
    When: Importing alert rule created using lacework api.
    Then: Alert rule created should be found in terraform plan.

    Args:
        load_lacework_tf_module: loads given TF module.
        lw_apiv1_resource: creates alert rule using lacework api v1.
    """
    # the resource name is used as the id for alert rule from API side.
    resource_name = lw_apiv1_resource._resource_name
    resource_id = lw_apiv1_resource.find_id_by_name(resource_name)
    assert resource_id, f"Failed to find resource id for {resource_id}"

    load_lacework_tf_module.execute_command(
        "import", "lacework_alert_rule.example", resource_id)
    # tf imports the resource and plan compares the imported resource against existing configs.
    # so existing config will be shown as updates.
    plan = load_lacework_tf_module.plan()
    assert resource_id in plan, (
        f"Expected resource ID '{resource_id}' to be found in the terraform plan, "
        f"indicating that the alert rule created by the API was successfully imported. "
        f"Plan output: {plan}"
    )


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
def test_tf_plan_alert_rules_updated_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify when alert rule is managed by tf, updates using lacework api are reflected in tf plan.

    Given: Applied TF module and lacework api client
    When: Updating alert rule using lacework api
    Then: Updated alert rule should be found in the plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    alert_rule = alert_rules[0]

    # Get resource id from terraform module
    alert_rule_id = alert_rule.get("id")
    updates = {
        "filters": {
            "name": "Update_Alert_Name",
            "description": "Update_Description",
        }

    }

    resource_client = AlertRules(api_v2_client)

    resp = resource_client.update_resource(
        updates, resource_id=alert_rule_id
    )
    assert resp.status_code == 200, f"Failed to update alert rule: {resp.text}"

    plan = deploy_lacework_tf_module.plan()
    assert (
        "Update_Alert_Name" in plan
    ), f"updated alert name not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
def test_tf_plan_alert_rules_updated_by_apiv1(api_v1_client, deploy_lacework_tf_module):
    """Verify when alert rule is managed by tf, updates using lacework api are reflected in tf plan.

    Given: Applied TF module and lacework api client
    When: Updating alert rule using lacework api
    Then: Updated alert rule should be found in the plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    alert_rule = alert_rules[0]

    # Get resource id from terraform module
    alert_rule_id = alert_rule.get("id")

    # Find resource object from API
    resource_client = AlertRulesV1(api_v1_client)
    alert_rule_from_api = resource_client.list_all_resource().json()["data"]
    alert_rule_from_api = [
        rule for rule in alert_rule_from_api if rule["MC_GUID"] == alert_rule_id
    ][0]

    # update the event category to Kubernetes Activity
    alert_rule_from_api["FILTERS"]["eventCategory"] = ["Kubernetes Activity"]

    resp = resource_client.update_resource(
        alert_rule_from_api
    )
    assert resp.status_code == 200, f"Failed to update alert rule: {resp.text}"

    plan = deploy_lacework_tf_module.plan()

    assert (
        "~ update in-place" in plan
    ), f"updated alert name not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
def test_tf_plan_alert_rules_deleted_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify alert rule deleted using lacework api is not found in the list returned by LW API.

    Given: Lacework api client
    When: Deleting alert rule using lacework api
    Then: Alert rule deleted should be reflected in terraform plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    alert_rule = alert_rules[0]
    alert_rule_id = alert_rule.get("id")
    resp = AlertRules(api_v2_client).delete_resource(alert_rule_id)
    assert resp.status_code == 204, f"Failed to delete alert rule: {resp.text}"
    # When resource is deleted using LW API,
    # local config will be shown as updates (+create) in the plan.
    plan = deploy_lacework_tf_module.plan()
    assert (
        "+ create" in plan
    ), f"alert rule creation should be found in the plan diff: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
def test_tf_plan_alert_rules_deleted_by_apiv1(api_v1_client, deploy_lacework_tf_module):
    """Verify alert rule deleted using lacework api is not found in the list returned by LW API.

    Given: Lacework api client
    When: Deleting alert rule using lacework api
    Then: Alert rule deleted should be reflected in terraform plan.

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_rules = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_rules()
    alert_rule = alert_rules[0]
    alert_rule_id = alert_rule.get("id")
    resp = AlertRulesV1(api_v1_client).delete_resource(alert_rule_id)
    assert resp.status_code == 200, f"Failed to delete alert rule: {resp.text}"
    # When resource is deleted using LW API,
    # local config will be shown as updates (+create) in the plan.
    plan = deploy_lacework_tf_module.plan()
    assert (
        "+ create" in plan
    ), f"alert rule creation should be found in the plan diff: {plan}"
