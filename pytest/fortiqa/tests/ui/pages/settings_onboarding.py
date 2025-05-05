"""Settings Onboarding page"""

import logging
import json
import os
from time import sleep

from fortiqa.tests import settings
from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.work_with_files import Files
from fortiqa.tests.ui.tests.settings.test_onboarding import agentless_allregions

logger = logging.getLogger(__name__)
info = logging.getLogger(__name__).info

onboarding_section = '//button//div[text()="visible_text" and @role="heading"]'
cld_acc_selection = '//div[contains(@data-testid,"createacct-create")]//*[contains(text(),"cld_service")]'
config_method = cld_acc_selection + '/../../..//span[contains(text(),"config_method")]'
discovery_summary = '//ul[@class="Deployment_summary__afACu"]//div[contains(text(),"summary_detail")]/../div[2]'
checklist_result = '//div[contains(text(),"AWS integration_name Checklist")]/../span'
checklist_details = '//div[@role="status"]//div[@class="trellis-banner-text"]'
alert_text = '//div[@role="alert"]'
integration_success_text = '//div[contains(@class,"trellis-banner-success")]'
integration_rollback_text = '//div[contains(@class,"trellis-banner-warn")]'


class SettingsOnboardingPage(BaseUiHelper):
    """Settings Onboarding page"""

    def open_onboarding(self, name: str):
        """
        Open the Onboarding page
        :param name: Name of the onboarding section
        """
        self.open_page("Onboarding")
        self.click(onboarding_section.replace("visible_text", name))
        expected_url = "https://" + settings.app.customer[
            "account_name"] + ".lacework.net/ui/welcome/workflow/cloudaccounts"
        self.verify_url(expected_url)

    def go_to_new_aws_integration_page(self):
        """Go to 'New cloud integration page' for AWS account"""
        self.open_onboarding("Configure cloud accounts")

        info("Select method")
        self.click(cld_acc_selection.replace("cld_service", "Amazon Web Services"))
        self.click(config_method.replace("cld_service", "Amazon Web Services").replace("config_method",
                                                                                       "Automated configuration"))
        self.click_btn("Next")

    def fill_new_cloud_integration_form(self, data: dict, roll_back: bool = False):
        """
        Fill AWS new cloud integration form.
        :param data: Specified data for integration method, AWS credentials
        :param roll_back: True for fill form for Roll Back
        """
        if roll_back:
            method = ""
            match data["integration_method"]:
                case "Agentless Workload Scanning":
                    method = "Agentless"
                case "Configuration":
                    method = "Config"
                case "CloudTrail":
                    method = "CloudTrail"
            self.set_checkbox(f'AWS {method}', True)
        else:
            for method in ["Agentless Workload Scanning", "Configuration", "CloudTrail"]:
                self.set_checkbox(method, False)
            if data["integration_method"]:
                self.set_checkbox(data["integration_method"], True)
        self.set_text_field("Access key ID", data["access_key_id"])
        self.set_text_field("Secret access key", data["secret_access_key"])
        self.set_text_field("Session token", data["session_token"])
        if self.get_dropdown_list_value("Default Region") != data["default_region"]:
            self.open_dropdown_list("Default Region")
            self.click_by_text(data["default_region"], position="last()", partial=True)

    def aws_integration(self, integration_data: dict, aws_integration_context=None, roll_back: bool = False):
        """
        AWS accounts automated integration
        :param integration_data: Specified data for integration method, AWS credentials
        :param aws_integration_context: Fixture that provides integration context and handles cleanup.
        :param roll_back: True for verifying Roll Back from UI
        """
        info(f"aws_integration(), {integration_data=}, {roll_back=}")
        self.go_to_new_aws_integration_page()

        info("Prepare. Fill integration data.")
        self.fill_new_cloud_integration_form(integration_data)
        self.click_btn("Next")
        sleep(5)

        info("Review. Verify discovery result.")
        # Discovery Summary
        aws_account = settings.app.aws_account.aws_account_id
        caller_identity = f'arn:aws:sts::{aws_account}:assumed-role/.+/session[0-9]+'
        error = self.verify_text(discovery_summary.replace("summary_detail", "Caller Identity"), caller_identity,
                                 re_pattern=True)
        actual_caller_identity = self.get_text(discovery_summary.replace("summary_detail", "Caller Identity"))
        error += self.verify_text(discovery_summary.replace("summary_detail", "AWS Account"), aws_account)
        error += self.verify_text(discovery_summary.replace("summary_detail", "AWS Organization Access"),
                                  "PERMISSION DENIED")
        error += self.verify_text(discovery_summary.replace("summary_detail", "CloudTrail Name"), "NOT DETECTED")
        error += self.verify_text(discovery_summary.replace("summary_detail", "EKS Clusters"), "0")
        error += self.verify_text(discovery_summary.replace("summary_detail", "Enabled Regions"),
                                  ",".join(region for region in agentless_allregions) if
                                  "Agentless" in integration_data["integration_method"] else "NOT DETECTED")

        # AWS checklist result
        integration_name = ""
        match integration_data["integration_method"]:
            case "Agentless Workload Scanning":
                integration_name = "Agentless"
            case "Configuration":
                integration_name = "Compliance"
            case "CloudTrail":
                integration_name = "CloudTrail"
        error += self.verify_text(checklist_result.replace("integration_name", integration_name),
                                  "Ready to integrate")
        error += self.verify_button_status("Back", True)
        error += self.verify_button_status("Integrate", True)
        assert not error, error

        info("Integrate.")
        self.click_btn("Integrate")
        sleep(5)
        current_url = self.driver.current_url
        info(f"Deployment URL={current_url}")
        deployment_client = aws_integration_context.deployment_client
        deployment_id = current_url.split("/")[-1]
        aws_integration_context.deployment_id = deployment_id

        integration_sse = deployment_client.get_sse(channel=deployment_id)

        # Wait until integration complete
        resp = deployment_client.pull_integration(deployment_id=deployment_id)
        aws_integration_context.workspace_ids = [integration['workspace_id'] for integration in resp['integrations']]
        integration_logs = "\n".join(
            f"Name: {integration.get('name', 'N/A')}, "
            f"Status: {integration.get('status', 'N/A')}, "
            f"Error: {integration.get('error', 'N/A')}"
            for integration in resp['integrations']
        )
        logger.debug(f'Integration status: {integration_logs=}')
        assert (
                resp['status'] == 'succeeded' and
                all(integration['status'] == 'succeeded' for integration in resp['integrations'])
        ), (
            'Integration failed:'
            f"{resp['status']=} "
            f"{integration_logs=} "
            f"SSE message: {integration_sse['messages']}"
        )
        self.wait_until_loading_sign_disappears(timeout=30)

        error += self.verify_text(integration_success_text,
                                  "Integrations completed\nHere are the integrations and resources Lacework has created")
        error += self.verify_text(discovery_summary.replace("summary_detail", "Account ID"), aws_account)
        error += self.verify_text(discovery_summary.replace("summary_detail", "Account Principal"),
                                  actual_caller_identity)
        if integration_name == "Compliance":
            integration_name = "Config"
        error += self.verify_text(checklist_result.replace("integration_name Checklist", integration_name), "Succeeded")
        assert not error, error

        if not os.environ.get("GITHUB_ACTIONS"):
            # Download TF file
            self.click_by_text("Download Terraform files")
            Files().verify_file(prefix="tf-files", suffix="gz", driver=self.driver)
            info(f"Downloaded Terraform files for {deployment_id=}")

        if roll_back:
            info("Rollback")
            self.click_btn("Roll Back")
            sleep(1)
            self.fill_new_cloud_integration_form(integration_data, roll_back=True)
            self.click_btn("Submit")
            sleep(5)
            delete_sse = deployment_client.get_sse(channel=deployment_id)
            resp = deployment_client.pull_integration(deployment_id=deployment_id)
            assert resp['status'] == 'rolled-back' and all(
                integration['status'] == 'rolled-back' for integration in resp['integrations']), \
                (
                    'Not all delete integrations were successful\n'
                    f"{resp['status']=}\n"
                    f"SSE response data:\n{json.dumps(delete_sse, indent=4)}"
                )
            self.wait_until_loading_sign_disappears(timeout=30)
            error += self.verify_text(integration_rollback_text, "All integrations are rolled back")
            error += self.verify_text(discovery_summary.replace("summary_detail", "Account ID"), aws_account)
            error += self.verify_text(discovery_summary.replace("summary_detail", "Account Principal"),
                                      actual_caller_identity)
            error += self.verify_text(checklist_result.replace("integration_name Checklist", integration_name),
                                      "Rolled-Back")
            assert not error, error
        self.click_btn("Exit")

    def aws_integration_with_expired_iam_session(self, integration_data: dict):
        """
        AWS accounts automated integration with expired IAM session.
        :param integration_data: Specified data for integration method, AWS credentials
        """
        info(f"aws_integration_with_expired_iam_session(), {integration_data=}")
        self.go_to_new_aws_integration_page()

        info("Prepare. Fill integration data.")
        self.fill_new_cloud_integration_form(integration_data)
        self.click_btn("Next")
        sleep(1)

        info("Review. Verify discovery result.")
        error_msg = ("Failed to proceed\n"
                     "invalid CSP credentials: failed to setup AWS client: failed to get caller identity: operation "
                     "error STS: GetCallerIdentity, https response error StatusCode: 403, "
                     "RequestID: [a-z0-9-]+, api error ExpiredToken: "
                     "The security token included in the request is expired")
        error = self.verify_text(alert_text, error_msg, re_pattern=True)
        error += self.verify_button_status("Back", True)
        error += self.verify_button_status("Integrate", False)
        assert not error, error

    def aws_integration_with_missing_permission(self, integration_data: dict, missing_permission: str):
        """
        AWS accounts automated integration with missing permission.
        :param integration_data: Specified data for integration method, AWS credentials
        """
        info(f"aws_integration_with_missing_permission(), {integration_data=}, {missing_permission=}")
        self.go_to_new_aws_integration_page()

        discovery_failed = False
        for integration_method in ["Agentless Workload Scanning", "Configuration", "CloudTrail"]:
            info("Prepare. Fill integration data.")
            integration_data["integration_method"] = integration_method
            self.fill_new_cloud_integration_form(integration_data)
            self.click_btn("Next")
            sleep(5)

            info("Review. Verify discovery result.")
            integration_name = ""
            match integration_data["integration_method"]:
                case "Agentless Workload Scanning":
                    integration_name = "Agentless"
                case "Configuration":
                    integration_name = "Compliance"
                case "CloudTrail":
                    integration_name = "CloudTrail"
            discovery_result = self.get_text(checklist_result.replace("integration_name", integration_name))
            error = ""
            if discovery_result == "Not ready to integrate":
                discovery_failed = True
                info(f"{integration_method} discovery failed due to missing permission.")
                error_msg = ("Some integrations are not ready\n"
                             "We cannot proceed with all integrations. Please fix the errors and try again.")
                error += self.verify_text(alert_text, error_msg)
                for warning in self.get_elements(checklist_details):
                    error += self.verify_text(actual_text=warning.text,
                                              expected_text=f"Required permission missing {missing_permission}",
                                              partial=True)
                error += self.verify_button_status("Back", True)
                error += self.verify_button_status("Integrate", False)
            elif discovery_result == "Ready to integrate":
                info(f"{integration_method} discovery success.")
                error += self.verify_button_status("Back", True)
                error += self.verify_button_status("Integrate", True)
            self.click_btn("Back")
            assert not error, error

        assert discovery_failed, (f"Expected at least one integration discovery failed due to {missing_permission=}, "
                                  f"however, all discovery are passed.")

    def aws_integration_with_invalid_data(self, integration_data: dict):
        """
        AWS accounts automated integration with invalid data
        :param integration_data: Specified data for integration method, AWS credentials
        """
        info(f"aws_integration(), {integration_data=}")
        self.go_to_new_aws_integration_page()

        info("Prepare. Fill integration data.")
        self.fill_new_cloud_integration_form(integration_data)
        self.click_btn("Next")
        sleep(5)

        info("Verify error messages.")
        error_msg = ("Failed to proceed\n"
                     "invalid CSP credentials: failed to setup AWS client: failed to get caller identity: operation "
                     "error STS: GetCallerIdentity, https response error StatusCode: 403, "
                     "RequestID: [a-z0-9-]+, api error InvalidClientTokenId: "
                     "The security token included in the request is invalid.")
        error = self.verify_text(alert_text, error_msg, re_pattern=True)
        error += self.verify_button_status("Back", True)
        error += self.verify_button_status("Integrate", False)
        assert not error, error

    def aws_integration_with_empty_data(self, integration_data: dict, empty_method: bool = False):
        """
        AWS accounts automated integration with empty data
        :param integration_data: Specified data for integration method, AWS credentials
        :param empty_method: True for integration method not selected
        """
        info(f"aws_integration(), {integration_data=}, {empty_method=}")
        self.go_to_new_aws_integration_page()

        info("Prepare. Fill integration data.")
        self.fill_new_cloud_integration_form(integration_data)
        self.click_btn("Next")
        sleep(5)

        info("Verify error messages.")
        if empty_method:
            error = self.verify_text(alert_text, "Failed to proceed\nintegrations cannot be empty")
            error += self.verify_button_status("Back", True)
            error += self.verify_button_status("Integrate", False)
        else:
            error = self.verify_text_field_error_message("Access key ID", "Access key ID is required")
            error += self.verify_text_field_error_message("Secret access key", "Secret access key is required")
            error += self.verify_text_field_error_message("Session token", "Session token is required")
            error += self.verify_button_status("Cancel", True)
            error += self.verify_button_status("Next", True)
        assert not error, error
