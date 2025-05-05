import json
import logging

import pytest

from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.lw.apiv2.api_client.report_rules.report_rules import ReportRules
from fortiqa.libs.lw.apiv1.api_client.report_rules.report_rules import ReportRules as ReportRulesV1
from fortiqa.libs.data.report_rules import ReportRuleData

logger = logging.getLogger(__name__)


new_rule = {
    "type": "Report",
    "intgGuidList": [
            "SYSTEME2_7794AF3EBA2D0D28CC5403A91C4CF2C89438B17648BB662"
        ],
    "reportNotificationTypes": {
        "awsCisS3": True
    },
    "filters": {
        "name": "new report rule",
        "description": "new report rule description",
        "enabled": 1
    }
}


class TestReportRules:

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    def test_tf_apply_report_rules_check_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify report rules created using lacework TF provider are returned by LW API.

        Given: TF module with report rules pre-deployed.
        When: Listing existing report rules using LW API.
        Then: Report rules deployed by terraform should be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            deploy_lacework_tf_module: TF module with report rules pre-deployed.
        """
        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()

        resp = ReportRules(api_v2_client).list_all_resource()
        report_rules_from_api = json.loads(resp.text)['data']

        not_found = []
        for report_rule in report_rules:
            from_tf = ReportRuleData.from_tf(report_rule)
            found = False
            for api_report_rule in report_rules_from_api:
                from_api = ReportRuleData.from_api(api_report_rule)
                if from_tf.match(from_api):
                    found = True
            if not found:
                not_found.append(report_rule)

        assert not not_found, f"Report rules not found: {not_found}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    @pytest.mark.parametrize(
        "new_report_rules",
        [
            {
                "report_rule_name": "NewReportRule",
            }
        ],
    )
    def test_tf_apply_updated_report_rules_check_apiv2(
        self, deploy_lacework_tf_module, new_report_rules, api_v2_client
    ):
        """Verify update in terraform module is reflected in the plan.

        Given: Applied TF module and modified report rules.
        When: Updating report rules using TF module.
        Then: Updated report rules should be found in the diff.

        Args:
            deploy_lacework_tf_module: deploys/destroys given TF module.
            new_report_rules: new report rule details.
            api_v2_client: API V2 client for interacting with the Lacework.
        """
        deploy_lacework_tf_module.apply(tf_vars=new_report_rules, use_cache=False)

        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()
        resp = ReportRules(api_v2_client).list_all_resource()
        report_rules_from_api = json.loads(resp.text)["data"]

        not_found = []
        change_found_in_tf = False
        for report_rule in report_rules:
            found = False
            from_tf = ReportRuleData.from_tf(report_rule)
            # Check if changed name is found in API response.
            if new_report_rules["report_rule_name"] in json.dumps(from_tf.__dict__):
                change_found_in_tf = True
            for api_report_rule in report_rules_from_api:
                if from_tf.match(ReportRuleData.from_api(api_report_rule)):
                    found = True
            if not found:
                not_found.append(report_rule)
        assert len(not_found) == 0, f"Report rules {not_found} were not in API response"
        assert change_found_in_tf, f"Report rules {new_report_rules} not found in TF resource"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    @pytest.mark.parametrize(
        "new_report_rule",
        [
            {
                "report_rule_name": "new report rule",
            }
        ]
    )
    def test_tf_plan_updated_report_rules(self, deploy_lacework_tf_module, new_report_rule):
        """Verify update in terraform module is reflected in the plan.

        Given: Applied TF module and modified report rule.
        When: Updating report rule using TF module.
        Then: Updated report rule should be found in the diff.

        Args:
            deploy_lacework_tf_module: deploys/destroys given TF module.
            new_report_rule: list of new report rules to be added.
        """
        plan = deploy_lacework_tf_module.plan(tf_vars=new_report_rule)
        assert new_report_rule["report_rule_name"] in plan, f"Report rule not found in plan: {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    def test_tf_destroy_report_rules_check_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify report rules deleted using terraform module are not found in LW API.

            Given: Applied TF module with report rules.
            When: Deleting report rules using TF module.
            Then: Deleted report rules should not be found in the list returned by API.

            Args:
                api_v2_client: API V2 client for interacting with the Lacework.
                deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()
        # Delete the report rules using tf module
        deploy_lacework_tf_module.destroy()
        resp = ReportRules(api_v2_client).list_all_resource()
        report_rules_from_api = json.loads(resp.text)['data']
        not_found = []
        for report_rule in report_rules:
            found = False
            from_tf = ReportRuleData.from_tf(report_rule)
            for api_report_rule in report_rules_from_api:
                if from_tf.match(ReportRuleData.from_api(api_report_rule)):
                    found = True
            if found:
                not_found.append(report_rule)
        assert (
            len(not_found) == 0
        ), f"Deleted channels {not_found} were found in API response {report_rules_from_api}"

    @pytest.mark.parametrize("load_lacework_tf_module", ["report_rule"], indirect=True)
    @pytest.mark.parametrize(
        "lw_api_create_delete_resource",
        [
            {"api_client_type": ReportRules, "payload": new_rule}
        ],
        indirect=True
    )
    def test_tf_import_report_rules_created_by_apiv2(self, lw_api_create_delete_resource, load_lacework_tf_module):
        """
        Test the import functionality of Terraform for Lacework report rules.
        This test verifies that a report rule created via the Lacework API can be
        successfully imported into Terraform.

        Given:
            - A new report rule created using the Lacework API.
        When:
            - Importing the report rule into Terraform using its ID.
        Then:
            - The Terraform plan should show no changes if the report rule name matches
            the expected name.
            - The report rule name should be present in the Terraform plan if it does
            not match the expected.

        Args:
            lw_api_create_delete_resource: Fixture that handles the creation and deletion
                of the report rule resource using the Lacework API.
            load_lacework_tf_module: Fixture that loads the Terraform module for Lacework.
        """
        report_rule_name = lw_api_create_delete_resource._resource_name
        report_rule_id = lw_api_create_delete_resource.find_id_by_name(report_rule_name)
        assert report_rule_id, f"Report rule not found in API response: {report_rule_name}"
        load_lacework_tf_module.execute_command(
            "import", "lacework_report_rule.aws", report_rule_id)
        plan = load_lacework_tf_module.plan()
        assert (report_rule_name in plan), f"Changes should be found in plan: {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    def test_tf_plan_report_ruless_updated_by_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify when report rules are managed by tf, updates using lacework api are reflected in tf plan.

            Given: Applied TF module and lacework api client
            When: Updating report rules using lacework api
            Then: Updated report rules should be found in the plan.

            Args:
                api_v2_client: API V2 client for interacting with the Lacework
                deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()
        report_rule = report_rules[0]

        report_rule_id = report_rule["id"]
        updates = {
            "filters": {
                "description": "Update new description"
            }
        }

        resource_client = ReportRules(api_v2_client)

        resp = resource_client.update_resource(
            updates, resource_id=report_rule_id
        )
        assert resp.status_code == 200, f"Failed to update report rule: {resp.text}"

        plan = deploy_lacework_tf_module.plan()

        assert ("~ update in-place" in plan), f"in-place update should be found in plan: {plan}"
        assert (
            "\"Update new description\" ->" in plan
        ), f"Override existing description shoud be found in plan: {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    def test_tf_plan_report_rules_deleted_by_apiv2(self, api_v2_client, deploy_lacework_tf_module):
        """Verify report rules deleted using lacework api is not found in the list returned by LW API.

        Given: Lacework api client
        When: Deleting report rules using lacework api
        Then: Report rules deleted should be reflected in terraform plan.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework
            deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()
        report_rule = report_rules[0]
        report_rule_id = report_rule["id"]
        resp = ReportRules(api_v2_client).delete_resource(report_rule_id)
        assert resp.status_code == 204, f"Failed to delete report rules: {resp.text}"
        # When resource is deleted using LW API,
        # local config will be shown as updates (+create) in the plan.
        plan = deploy_lacework_tf_module.plan()

        assert (
            "+ create" in plan
        ), f"creation of new resource should be found in the plan diff: {plan}"

    @pytest.mark.parametrize("deploy_lacework_tf_module", ["report_rule"], indirect=True)
    def test_tf_plan_report_rules_severity_updated_by_apiv1(self, api_v1_client, deploy_lacework_tf_module):
        """Verify when report rules are managed by tf, updates using lacework api are reflected in tf plan.

            Given: Applied TF module and lacework api client
            When: Updating report rules using lacework api
            Then: Updated report rules should be found in the plan.

            Args:
                api_v1_client: API V1 client for interacting with the Lacework
                deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()
        report_rule = report_rules[0]

        report_rule_id = report_rule["id"]
        # get all report rules using api and find the one matching the id
        resp = ReportRulesV1(api_v1_client).get_all_report_rules()
        report_rules_from_api = json.loads(resp.text)["data"]
        report_rule_from_api = None
        for api_report_rule in report_rules_from_api:
            if api_report_rule["MC_GUID"] == report_rule_id:
                report_rule_from_api = api_report_rule
                break
        assert report_rule_from_api, f"Report rule not found in API response: {report_rule_id}"
        # update serivity of the report rule
        report_rule_from_api["FILTERS"]["severity"] = [1, 2, 3, 4]

        resource_client = ReportRulesV1(api_v1_client)

        resp = resource_client.update_report_rules(
            report_rule_from_api
        )
        assert resp.status_code == 200, f"Failed to update report rule: {resp.text}"

        plan = deploy_lacework_tf_module.plan()

        assert ("~ update in-place" in plan), f"in-place update should be found in plan: {plan}"

    @pytest.mark.xfail(
        reason="bug in lacework APIv1 - https://github.com/lacework/terraform-provider-lacework/issues/475"
    )
    @pytest.mark.parametrize(
        "deploy_lacework_tf_module", ["report_rule"], indirect=True
    )
    def test_tf_plan_report_rules_report_type_updated_by_apiv1(self, api_v1_client, deploy_lacework_tf_module):
        """Verify when report rules are managed by tf, updates using lacework api are reflected in tf plan.

            Given: Applied TF module and lacework api client
            When: Updating report rules using lacework api
            Then: Updated report rules should be found in the plan.

            Args:
                api_v1_client: API V1 client for interacting with the Lacework
                deploy_lacework_tf_module: deploys/destroys given TF module.
        """
        report_rules = TFParser(
            working_dirs=[deploy_lacework_tf_module.tfdir]
        ).get_lw_report_rules()
        report_rule = report_rules[0]

        report_rule_id = report_rule["id"]
        # get all report rules using api and find the one matching the id
        resp = ReportRulesV1(api_v1_client).get_all_report_rules()
        report_rules_from_api = json.loads(resp.text)["data"]
        report_rule_from_api = None
        for api_report_rule in report_rules_from_api:
            if api_report_rule["MC_GUID"] == report_rule_id:
                report_rule_from_api = api_report_rule
                break
        assert report_rule_from_api, f"Report rule not found in API response: {report_rule_id}"
        # update report notification type of the report rule
        report_rule_from_api["REPORT_NOTIFICATION_TYPES"] = {
            "AWS_CIS_S3": False,
            "AWS_COMPLIANCE_EVENTS": True,
            "HOST_VULNERABILITY_REPORT": True,
            "CONTAINER_VULNERABILITY_REPORT": True,
        }

        resource_client = ReportRulesV1(api_v1_client)

        resp = resource_client.update_report_rules(
            report_rule_from_api
        )
        assert resp.status_code == 200, f"Failed to update report rule: {resp.text}"

        plan = deploy_lacework_tf_module.plan()

        assert ("~ update in-place" in plan), f"in-place update should be found in plan: {plan}"
