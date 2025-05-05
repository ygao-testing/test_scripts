"""AWS Cloudtrail page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.webelements_helper import button

info = logging.getLogger(__name__).info


class AwsCloudTrailPage(BaseUiHelper):
    """AWS Cloudtrail page"""

    def verify_aws_cloudtrail_page(self):
        """Verify the AWS Cloudtrail page"""
        info("1. Open 'AWS Cloudtrail' page.")
        self.open_page("AWS Cloudtrail")

        if self.is_element_present(button.replace("visible_text", "Go to Onboarding")):
            info("AWS account is not set up.")
            error = self.verify_text(
                xpath='//div[@id="DossierCardContainerScrolling"]',
                expected_text="Complete setting up your Lacework account\n"
                              "Live data will appear here in a maximum of 2 hours\n"
                              "In the meantime, check out other great materials Lacework offers\n"
                              "Go to Onboarding"
            )
            assert not error, error
            return

        active_high_priority_alerts_table = self.move_to_table_and_get_data("Active High-Priority Alerts",
                                                                            move_down=True)
        cloudtrail_logs_table = self.move_to_table_and_get_data("CloudTrail logs")
        user_details_table = self.move_to_table_and_get_data("User details")
        user_events_table = self.move_to_table_and_get_data("User events")
        api_error_events_table = self.move_to_table_and_get_data("API error events")
        info(f"{active_high_priority_alerts_table=}\n{cloudtrail_logs_table=}\n{user_details_table=}\n"
             f"{user_events_table=}\n{api_error_events_table=}")
