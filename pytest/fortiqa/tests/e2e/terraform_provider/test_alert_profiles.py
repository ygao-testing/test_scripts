import json
import logging

import pytest

from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.lw.apiv2.api_client.alert_profiles.alert_profiles import AlertProfiles
from fortiqa.libs.data.alert_profiles import AlertProfileData

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_profile"], indirect=True)
def test_tf_apply_alert_profiles_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify alert profiles applied using the lacework TF provider are returned by LW API V2.

    Given: Applied TF module with 'lacework_alert_profiles' resource[s].
    When: Listing existing alert profiles using LW API.
    Then: Alert profiles deployed by terraform should be found in the list returned by API V2.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_profiles = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_profiles()
    resp = AlertProfiles(api_v2_client).list_all_resource()
    alert_profiles_from_api = json.loads(resp.text)["data"]

    not_found = []
    for alert_profile in alert_profiles:
        found = False
        from_tf = AlertProfileData.from_tf(alert_profile)
        for api_alert_profile in alert_profiles_from_api:
            if from_tf.match(AlertProfileData.from_api(api_alert_profile)):
                found = True
        if not found:
            not_found.append(alert_profile)
    assert len(not_found) == 0, f"Alert rules {not_found} were not in API response"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_profile"], indirect=True)
@pytest.mark.parametrize(
    "new_profiles",
    [
        {"alert_name": "CustomViolation"},
        {"alert_name": "SecurityAlert"},
    ],
)
def test_tf_apply_updated_alert_profiles_check_apiv2(
    deploy_lacework_tf_module, new_profiles, api_v2_client
):
    """Verify update in terraform module is found in LW API.

    Given: Applied TF module and modified alert profile.
    When: Updating alert profile using TF module.
    Then: Updated alert profile should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        new_profiles: new alert profile details.
        api_v2_client: API V2 client for interacting with the Lacework.
    """
    deploy_lacework_tf_module.apply(tf_vars=new_profiles, use_cache=False)

    alert_profiles = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_profiles()
    resp = AlertProfiles(api_v2_client).list_all_resource()
    alert_profiles_from_api = json.loads(resp.text)["data"]

    not_found = []
    change_found_in_tf = False
    for alert_profile in alert_profiles:
        found = False
        from_tf = AlertProfileData.from_tf(alert_profile)
        for alert in from_tf.alerts:
            # Check if changed name is found in API response.
            if new_profiles["alert_name"] in json.dumps(alert.__dict__):
                change_found_in_tf = True
        for api_alert_profile in alert_profiles_from_api:
            if from_tf.match(AlertProfileData.from_api(api_alert_profile)):
                found = True
        if not found:
            not_found.append(alert_profile)
    assert len(not_found) == 0, f"Alert rules {not_found} were not in API response"
    assert change_found_in_tf, f"Alert profile {new_profiles} not found in TF resource"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_profile"], indirect=True)
@pytest.mark.parametrize(
    "new_profiles",
    [
        {"alert_profile_name": "newalertprofile", "alert_name": "CustomViolation"},
        {"alert_profile_name": "securityprofile", "alert_name": "SecurityAlert"},
    ],
)
def test_tf_plan_updated_alert_profiles(deploy_lacework_tf_module, new_profiles):
    """Verify update in terraform module is reflected in the plan.

    Given: Applied TF module and modified alert profile.
    When: Updating alert profile using TF module.
    Then: Updated alert profile should be found in the diff.

    Args:
        deploy_lacework_tf_module: deploys/destroys given TF module.
        new_profiles: new alert profile details.
    """
    # Passing new alert profile using tf_vars,
    # Simulating resource update using tf module
    plan = deploy_lacework_tf_module.plan(tf_vars=new_profiles)
    assert (
        new_profiles["alert_profile_name"] in plan
    ), f"alert profile not found in plan: {plan}"
    assert (
        new_profiles["alert_name"] in plan
    ), f"alert name not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_profile"], indirect=True)
def test_tf_destory_alert_profiles_check_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify alert profiles deleted using lacework_alert_profiles
       of the lacework TF provider are not found in the list returned by LW API.

    Given: Applied TF module with 'lacework_alert_profiles' resource[s].
    When: Deleting alert profiles using TF module.
    Then: Alert profiles deleted by terraform should not be found in the list returned by API.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_profiles = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_profiles()
    deploy_lacework_tf_module.destroy()
    resp = AlertProfiles(api_v2_client).list_all_resource()
    alert_profiles_from_api = json.loads(resp.text)["data"]
    found_profile = []
    for alert_profile in alert_profiles:
        found = False
        from_tf = AlertProfileData.from_tf(alert_profile)
        for api_alert_profile in alert_profiles_from_api:
            if from_tf.match(AlertProfileData.from_api(api_alert_profile)):
                found = True
        if found:
            found_profile.append(alert_profile)
    assert (
        len(found_profile) == 0
    ), f"Alert rules {found_profile} were found in API response"


new_lw_alert_profile = {
    "alertProfileId": "NEW_LW_ALERT_PROFILE_1",
    "extends": "LW_CFG_GCP_DEFAULT_PROFILE",
    "alerts": [
        {
            "name": "DefaultAlert",
            "eventName": "LW Host Entity File Default Alert",
            "description": "_OCCURRENCE Violation for file PATH on machine MID",
            "subject": "_OCCURRENCE violation detected for file PATH on machine MID"
        },
        {
            "name": "HE_File_Violation",
            "eventName": "LW Host Entity File Violation Alert",
            "description": "_OCCURRENCE Violation for file PATH on machine MID",
            "subject": "violation detected for file PATH on machine MID"
        }
    ]
}


@pytest.mark.parametrize("load_lacework_tf_module", ["alert_profile"], indirect=True)
@pytest.mark.parametrize(
    "lw_api_create_delete_resource",
    [{"api_client_type": AlertProfiles, "payload": new_lw_alert_profile}],
    indirect=True
)
def test_tf_import_alert_profiles_created_by_apiv2(load_lacework_tf_module, lw_api_create_delete_resource):
    """Verify alert profile created using lacework api can be imported in terraform.

    Given: TF module loaded with alert profile configuration.
    When: Importing alert profile created using lacework api.
    Then: Alert profile created should be found in terraform plan.

    Args:
        load_lacework_tf_module: loads given TF module.
        lw_api_create_delete_resource: creates alert profile using lacework api.
    """
    # the resource name is used as the id for alert profile from API side.
    resource_id = lw_api_create_delete_resource._resource_name
    assert resource_id, f"Failed to find resource id for {resource_id}"

    load_lacework_tf_module.execute_command(
        "import", "lacework_alert_profile.example", resource_id)
    # tf imports the resource and plan compares the imported resource against existing configs.
    # so existing config will be shown as updates.
    plan = load_lacework_tf_module.plan()
    assert resource_id in plan, (
        f"Expected resource ID '{resource_id}' to be found in the terraform plan, "
        f"indicating that the alert profile created by the API was successfully imported. "
        f"Plan output: {plan}"
    )


@pytest.mark.xfail(
    reason="Might be a bug in lacework API - https://github.com/lacework/terraform-provider-lacework/issues/645"
)
@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_profile"], indirect=True)
def test_tf_plan_alert_profiles_updated_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify when alert profile is managed by tf, updates using lacework api are reflected in tf plan.

    Given: Applied TF module and lacework api client
    When: Updating alert profile using lacework api
    Then: Updated alert profile should be found in the plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_profiles = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_profiles()
    alert_profile = alert_profiles[0]

    alert_profile_id = alert_profile["name"]
    updates = {
        "alerts": [
            {
                "name": "Update_Alert_Name",
                "eventName": "Update_Event_Name",
                "description": "Update_Description",
                "subject": "Update_Subject"
            }
        ]
    }

    resource_client = AlertProfiles(api_v2_client)

    resp = resource_client.update_resource(
        updates, resource_id=alert_profile_id
    )
    assert resp.status_code == 200, f"Failed to update alert profile: {resp.text}"

    plan = deploy_lacework_tf_module.plan()
    assert (
        "Update_Alert_Name" in plan
    ), f"updated alert name not found in plan: {plan}"


@pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_profile"], indirect=True)
def test_tf_plan_alert_profiles_deleted_by_apiv2(api_v2_client, deploy_lacework_tf_module):
    """Verify alert profile deleted using lacework api is not found in the list returned by LW API.

    Given: Lacework api client
    When: Deleting alert profile using lacework api
    Then: Alert profile deleted should be reflected in terraform plan.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    alert_profiles = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_alert_profiles()
    alert_profile = alert_profiles[0]
    alert_profile_id = alert_profile["name"]
    resp = AlertProfiles(api_v2_client).delete_resource(alert_profile_id)
    assert resp.status_code == 204, f"Failed to delete alert profile: {resp.text}"
    # When resource is deleted using LW API,
    # local config will be shown as updates (+create) in the plan.
    plan = deploy_lacework_tf_module.plan()
    assert (
        f"+ name    = \"{alert_profile_id}\"" in plan
    ), f"alert profile {alert_profile['name']} should be found in the plan diff: {plan}"
