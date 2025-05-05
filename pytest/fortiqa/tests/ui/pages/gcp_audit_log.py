"""GCP Audit Log page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.webelements_helper import button

info = logging.getLogger(__name__).info


class GcpAuditLogPage(BaseUiHelper):
    """GCP Audit Log page"""

    def verify_gcp_audit_log_page(self):
        """Verify the GCP Audit Log page"""
        info("1. Open 'GCP Audit Log' page.")
        self.open_page("GCP Audit Log")

        if self.is_element_present(button.replace("visible_text", "Go to Onboarding")):
            info("GCP account is not set up.")
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
        audit_logs_table = self.move_to_table_and_get_data("Audit logs")
        user_details_table = self.move_to_table_and_get_data("User details")
        api_error_events_table = self.move_to_table_and_get_data("API error events")
        info(f"{active_high_priority_alerts_table=}\n{audit_logs_table=}\n{user_details_table=}\n"
             f"{api_error_events_table=}")
