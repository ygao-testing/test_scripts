"""Workloads Containers page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class WorkloadsContainersPage(BaseUiHelper):
    """Workloads Containers page"""

    def verify_workloads_containers_page(self):
        """Verify the Workloads Containers page"""
        info("1. Open 'Workloads Containers' page.")
        self.open_page("Workloads Containers")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        list_of_active_containers_table = self.move_to_table_and_get_data("List of active containers")
        container_image_information_table = self.move_to_table_and_get_data("Container image information")
        command_line_by_executable_table = self.move_to_table_and_get_data("Command line by executable")
        active_listening_ports_table = self.move_to_table_and_get_data("Active listening ports")
        info(f"{alerts_table=}\n{list_of_active_containers_table=}\n{container_image_information_table=}\n"
             f"{command_line_by_executable_table=}\n{active_listening_ports_table=}")
