import json
import logging
import pytest
from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.lw.apiv2.api_client.alert_channels.alert_channels import AlertChannels
from fortiqa.libs.data.alert_channels import AlertChannelData

logger = logging.getLogger(__name__)
# TODO: move test data to a file
new_email_alert_channels = {
    "name": "new email alert channel",
    "type": "EmailUser",
    "enabled": 1,
    "data": {
        "notificationType": {},
        "channelProps": {
            "recipients": ["zqi@fortinet.com"]
        }
    }
}


class TestAlertChannels:
    """Test suite for verifying the functionality of Lacework alert channels using Terraform.

    This test suite includes the following tests:
    1. `test_tf_alert_channels`:
        Verifies that alert channels created using the Lacework Terraform provider are returned by the Lacework API.
    2. `test_tf_update_alert_channel`:
        Verifies that updates to alert channels in the Terraform module are reflected in the Terraform plan.
    3. `test_tf_delete_alert_channel`:
        Verifies that alert channels deleted using the Terraform module are not found in the Lacework API.
    4. `test_tf_import_alert_channel`:
        Tests the import functionality of Terraform for Lacework alert channels.
    """
    @pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
    def test_tf_apply_alert_channels_check_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify email alert channels created using lacework TF provider are returned by LW API.

        Given: TF module with email alert channels pre-deployed.
        When: Listing existing email alert channels using LW API.
        Then: Email alert channels deployed by terraform should be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            tf_lw_email_alert_channels: list of email alert channels deployed with terraform.
        """
        email_alert_channels = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_email_alert_channels()
        resp = AlertChannels(api_v2_client).list_all_resource()
        alert_channels_from_api = json.loads(resp.text)['data']

        not_found = []
        for email_alert_channel in email_alert_channels:
            found = False
            from_tf = AlertChannelData.from_tf(email_alert_channel)
            for api_alert_channel in alert_channels_from_api:
                from_api = AlertChannelData.from_api(api_alert_channel)
                if from_tf.match(from_api):
                    found = True
            if not found:
                not_found.append(email_alert_channel)
        assert (
            len(not_found) == 0
        ), f"Email alert channels {not_found} were not in API response {alert_channels_from_api}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
    @pytest.mark.parametrize(
        "new_email_alert_channels",
        [
            {"alert_channel_name": "NewEmailAlertChannel"}
        ]
    )
    def test_tf_apply_updated_alert_channels_check_apiv2(
        self, deploy_lacework_tf_module, new_email_alert_channels, api_v2_client
    ):
        """Verify update in terraform module is reflected in the plan.
        Given: Applied TF module and modified alert channel.
        When: Updating alert channel using TF module.
        Then: Updated alert channel should be found in the diff.
        Args:
            deploy_lacework_tf_module: deploys/destroys given TF module.
            new_email_alert_channels: list of new email alert channels to be added.
        """
        deploy_lacework_tf_module.apply(tf_vars=new_email_alert_channels)
        email_alert_channels = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_email_alert_channels()
        resp = AlertChannels(api_v2_client).list_all_resource()
        alert_channels_from_api = json.loads(resp.text)['data']

        not_found = []
        change_found_in_tf = False
        for email_alert_channel in email_alert_channels:
            found = False
            from_tf = AlertChannelData.from_tf(email_alert_channel)
            if new_email_alert_channels["alert_channel_name"] in json.dumps(from_tf.__dict__):
                change_found_in_tf = True
            for api_alert_channel in alert_channels_from_api:
                from_api = AlertChannelData.from_api(api_alert_channel)
                if from_tf.match(from_api):
                    found = True
            if not found:
                not_found.append(email_alert_channel)

        assert (
            len(not_found) == 0
        ), f"Email alert channels {not_found} were not in API response {alert_channels_from_api}"
        assert (
            change_found_in_tf
        ), f"Changes not found in TF module {email_alert_channels}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
    @pytest.mark.parametrize(
        "new_email_alert_channels",
        [
            {"alert_channel_name": "new email alert channel"}
        ]
    )
    def test_tf_plan_updated_alert_channels(
        self, deploy_lacework_tf_module, new_email_alert_channels
    ):
        """Verify update in terraform module is reflected in the plan.
        Given: Applied TF module and modified alert channel.
        When: Updating alert channel using TF module.
        Then: Updated alert channel should be found in the diff.
        Args:
            deploy_lacework_tf_module: deploys/destroys given TF module.
            new_email_alert_channels: list of new email alert channels to be added.
        """
        plan = deploy_lacework_tf_module.plan(tf_vars=new_email_alert_channels)

        assert (f"-> \"{new_email_alert_channels['alert_channel_name']}\"" in plan), \
            f"Email alert channel {new_email_alert_channels} not found in the plan {plan}"
        assert ("1 to change" in plan), f"Changes not found in plan {plan}"
        assert ("~ update in-place" in plan), f"Changes not found in plan {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
    def test_tf_destory_alert_channels_check_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify alert channels deleted using terraform module are not found in LW API.

        Given: Applied TF module with email alert channels.
        When: Deleting alert channels using TF module.
        Then: Deleted alert channels should not be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        email_alert_channels = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_email_alert_channels()
        # Delete the email alert channels using tf module
        deploy_lacework_tf_module.destroy()
        resp = AlertChannels(api_v2_client).list_all_resource()
        alert_channels_from_api = json.loads(resp.text)['data']
        not_found = []
        for email_alert_channel in email_alert_channels:
            found = False
            from_tf = AlertChannelData.from_tf(email_alert_channel)
            for api_alert_channel in alert_channels_from_api:
                if from_tf.match(AlertChannelData.from_api(api_alert_channel)):
                    found = True
            if found:
                not_found.append(email_alert_channel)
        assert (
            len(not_found) == 0
        ), f"Deleted channels {not_found} were found in API response {alert_channels_from_api}"

    @pytest.mark.parametrize("load_lacework_tf_module", ["alert_rule"], indirect=True)
    @pytest.mark.parametrize(
        "lw_api_create_delete_resource",
        [
            {"api_client_type": AlertChannels, "payload": new_email_alert_channels}
        ],
        indirect=True
    )
    def test_tf_import_alert_channels_created_by_apiv2(
        self, lw_api_create_delete_resource, load_lacework_tf_module
    ):
        """
        Test the import functionality of Terraform for Lacework alert channels.
        This test verifies that an alert channel created via the Lacework API can be
        successfully imported into Terraform.

        Given:
            - A new alert channel created using the Lacework API.
        When:
            - Importing the alert channel into Terraform using its ID.
        Then:
            - The Terraform plan should show no changes if the alert channel name matches
            the expected name.
            - The alert channel name should be present in the Terraform plan if it does
            not match the expected

        Args:
            lw_api_create_delete_resource: Fixture that handles the creation and deletion
                of the alert channel resource using the Lacework API.
            load_lacework_tf_module: Fixture that loads the Terraform module for Lacework.
        """
        alert_channel_name = lw_api_create_delete_resource._resource_name
        alert_channel_id = lw_api_create_delete_resource.find_id_by_name(alert_channel_name)
        assert alert_channel_id, f"Alert channel not found in API response: {alert_channel_name}"
        load_lacework_tf_module.execute_command(
            "import", "lacework_alert_channel_email.fortiqa_test", alert_channel_id)
        plan = load_lacework_tf_module.plan()

        assert (alert_channel_name in plan), f"Changes should be found in plan: {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
    def test_tf_plan_alert_channels_updated_by_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Test when alert channels are managed by tf, updates using api are reflected in the plan.

        Given:
            - Applied TF module with email alert channels.
        When:
            - Update alert channel using Lacework API.
        Then:
            - Updated alert channel should be found in the plan.

        Args:
            lw_api_create_delete_resource:
            - Fixture that manage alert channel resource using the Lacework API.
            deploy_lacework_tf_module:
            - Fixture that loads the Terraform module for Lacework.
        """
        alert_channels = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_email_alert_channels()
        alert_channel = alert_channels[0]

        alert_channel_id = alert_channel.get("intg_guid", None)

        updates = {
                "data": {
                    "channelProps": {
                        "recipients": ["zqi@fortinet.com"]
                    }
                }
            }

        resource_client = AlertChannels(api_v2_client)
        resp = resource_client.update_resource(updates, resource_id=alert_channel_id)
        assert resp.status_code == 200, f"Failed to update alert channel: {resp.text}"

        plan = deploy_lacework_tf_module.plan()
        assert ("~ update in-place" in plan), f"Changes not found in plan {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["alert_rule"], indirect=True)
    def test_tf_plan_alert_channels_deleted_by_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify alert channel deleted using Lacework API is not found in the list returned by LW API.

        Given: Lacework API client
        When: Deleting alert channel using Lacework API
        Then: Alert channel deleted should be reflected in Terraform plan.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework
            deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        alert_channels = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_email_alert_channels()
        alert_channel = alert_channels[0]
        alert_channel_id = alert_channel.get("intg_guid", None)
        resp = AlertChannels(api_v2_client).delete_resource(alert_channel_id)
        assert resp.status_code == 204, f"Failed to delete alert channel: {resp.text}"
        # When resource is deleted using LW API,
        # local config will be shown as updates (+create) in the plan.
        plan = deploy_lacework_tf_module.plan()
        # id was deleted so it is shown as null in the plan.
        assert (
            f"\"{alert_channel_id}\" -> null" in plan
        ), f"alert channel {alert_channel['name']} should be found in the plan diff: {plan}"
