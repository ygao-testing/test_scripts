"""Azure Activity log page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.webelements_helper import button

info = logging.getLogger(__name__).info


class AzureActivityLogPage(BaseUiHelper):
    """Azure Activity log page"""

    def verify_azure_activity_log_page(self):
        """Verify the Azure Activity log page"""
        info("1. Open 'Azure Activity Log' page.")
        self.open_page("Azure Activity Log")

        if self.is_element_present(button.replace("visible_text", "Go to Onboarding")):
            info("Azure account is not set up.")
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
        activity_logs_table = self.move_to_table_and_get_data("Activity logs")
        user_details_table = self.move_to_table_and_get_data("User details")
        api_error_events_table = self.move_to_table_and_get_data("API error events")
        info(f"{active_high_priority_alerts_table=}\n{activity_logs_table=}\n{user_details_table=}\n"
             f"{api_error_events_table=}")
