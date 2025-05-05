"""Workloads Hosts page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class WorkloadsHostsPage(BaseUiHelper):
    """Workloads Hosts page"""

    def verify_workloads_hosts_page(self):
        """Verify the Workloads Hosts page"""
        info("1. Open 'Workloads Hosts' page.")
        self.open_page("Workloads Hosts")

        info("2. Applications")
        self.click_tab("Applications")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        list_of_applications_table = self.move_to_table_and_get_data("List of applications")
        active_listening_ports_table = self.move_to_table_and_get_data("Active listening ports")
        executable_versions_table = self.move_to_table_and_get_data("Executable versions")
        command_line_by_executable_table = self.move_to_table_and_get_data("Command line by executable")
        applications_information_table = self.move_to_table_and_get_data("Applications information")
        list_of_active_containers_table = self.move_to_table_and_get_data("List of active containers")
        container_image_information_table = self.move_to_table_and_get_data("Container image information")
        info(f"{alerts_table=}\n{list_of_applications_table=}\n{active_listening_ports_table=}\n"
             f"{executable_versions_table=}\n{command_line_by_executable_table=}\n{applications_information_table=}\n"
             f"{list_of_active_containers_table=}\n{container_image_information_table=}")

        info("3. Files")
        self.click_tab("Files")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        list_of_changed_files_table = self.move_to_table_and_get_data("List of changed files")
        new_files_table = self.move_to_table_and_get_data("New files")
        new_registry_autoruns_table = self.move_to_table_and_get_data("New registry autoruns")
        known_malicious_files_table = self.move_to_table_and_get_data("Known malicious files")
        application_details_from_bad_files_table = self.move_to_table_and_get_data("Application details from bad files")
        command_line_by_file_table = self.move_to_table_and_get_data("Command line by file")
        package_installed_executables_table = self.move_to_table_and_get_data("Package installed executables")
        non_package_installed_executables_table = self.move_to_table_and_get_data("Non-Package installed executables")
        executable_versions_with_multiple_hashes_table = self.move_to_table_and_get_data(
            "Executable versions with multiple hashes")
        file_hash_summary_table = self.move_to_table_and_get_data("File hash summary")
        info(f"{alerts_table=}\n{list_of_changed_files_table=}\n{new_files_table=}\n{new_registry_autoruns_table=}\n"
             f"{known_malicious_files_table=}\n{application_details_from_bad_files_table=}\n"
             f"{command_line_by_file_table=}\n{package_installed_executables_table=}\n"
             f"{non_package_installed_executables_table=}\n{executable_versions_with_multiple_hashes_table=}\n"
             f"{file_hash_summary_table=}")

        info("4. Machines")
        self.click_tab("Machines")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        machine_properties_table = self.move_to_table_and_get_data("Machine properties")
        machine_tag_summary_table = self.move_to_table_and_get_data("Machine tag summary")
        machine_activity_table = self.move_to_table_and_get_data("Machine activity")
        list_of_external_facing_server_machines_table = self.move_to_table_and_get_data(
            "List of external facing server machines")
        tcp_table = self.move_to_table_and_get_data("TCP - client machines making external connections")
        upd_table = self.move_to_table_and_get_data("UDP - client machines making external connections")
        user_login_activity_table = self.move_to_table_and_get_data("User login activity")
        user_authentication_summary_table = self.move_to_table_and_get_data("User authentication summary")
        exposed_ports_table = self.move_to_table_and_get_data("Exposed ports")
        domain_lookups_by_machine_table = self.move_to_table_and_get_data("Domain lookups by machine")
        dropped_packets_summary_table = self.move_to_table_and_get_data("Dropped packets summary")
        list_of_active_executables_table = self.move_to_table_and_get_data("List of active executables")
        executable_information_table = self.move_to_table_and_get_data("Executable information")
        list_of_active_containers_table = self.move_to_table_and_get_data("List of active containers")
        container_image_information_table = self.move_to_table_and_get_data("Container image information")
        list_of_detected_secrets_table = self.move_to_table_and_get_data("List of detected secrets")
        info(f"{alerts_table=}\n{machine_properties_table=}\n{machine_tag_summary_table=}\n{machine_activity_table=}\n"
             f"{list_of_external_facing_server_machines_table=}\n{tcp_table=}\n{upd_table=}\n"
             f"{user_login_activity_table=}\n{user_authentication_summary_table=}\n{exposed_ports_table=}\n"
             f"{domain_lookups_by_machine_table=}\n{dropped_packets_summary_table=}\n"
             f"{list_of_active_executables_table=}\n{executable_information_table=}\n"
             f"{list_of_active_containers_table=}\n{container_image_information_table=}\n"
             f"{list_of_detected_secrets_table=}")

        info("5. Networks")
        self.click_tab("Networks")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        domain_lookups_table = self.move_to_table_and_get_data("Domain lookups")
        exposed_ports_table = self.move_to_table_and_get_data("Exposed ports")
        machine_properties_table = self.move_to_table_and_get_data("Machine properties")
        user_properties_table = self.move_to_table_and_get_data("User properties")
        server_ports_with_no_connection_table = self.move_to_table_and_get_data("Server ports with no connection")
        list_of_listening_servers_table = self.move_to_table_and_get_data("List of listening servers")
        list_of_external_facing_server_machines_table = self.move_to_table_and_get_data(
            "List of external facing server machines")
        client_machines_making_external_connections_table = self.move_to_table_and_get_data(
            "Client machines making external connections")
        tcp_table = self.move_to_table_and_get_data("TCP - client machines making external connections")
        udp_table = self.move_to_table_and_get_data("UDP - client machines making external connections")
        external_udp_connections_table = self.move_to_table_and_get_data("External UDP connections")
        ip_address_summary_table = self.move_to_table_and_get_data("IP address summary")
        dns_summary_table = self.move_to_table_and_get_data("DNS summary")
        resolved_ip_information_table = self.move_to_table_and_get_data("Resolved IP information")
        info(f"{alerts_table=}\n{domain_lookups_table=}\n{exposed_ports_table=}\n{machine_properties_table=}\n"
             f"{user_properties_table=}\n{server_ports_with_no_connection_table=}\n{list_of_listening_servers_table=}\n"
             f"{list_of_external_facing_server_machines_table=}\n{client_machines_making_external_connections_table=}\n"
             f"{tcp_table=}\n{udp_table=}\n{external_udp_connections_table=}\n{ip_address_summary_table=}\n"
             f"{dns_summary_table=}\n{resolved_ip_information_table=}")

        info("6. Processes")
        self.click_tab("Processes")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        unique_process_details_table = self.move_to_table_and_get_data("Unique process details")
        list_of_applications_table = self.move_to_table_and_get_data("List of applications")
        exposed_ports_table = self.move_to_table_and_get_data("Exposed ports")
        executable_versions_table = self.move_to_table_and_get_data("Executable versions")
        command_line_by_executable_table = self.move_to_table_and_get_data("Command line by executable")
        applications_information_table = self.move_to_table_and_get_data("Applications information")
        tcp_external_table = self.move_to_table_and_get_data("TCP - external client connection details")
        udp_external_table = self.move_to_table_and_get_data("UDP - external client connection details")
        tcp_internal_table = self.move_to_table_and_get_data("TCP - internal process connection details")
        udp_internal_table = self.move_to_table_and_get_data("UDP - internal process connection details")
        tcp_internal_from_internal_devices_without_agents_table = self.move_to_table_and_get_data(
            "TCP - internal connection details from internal devices without agents")
        upd_internal_from_internal_devices_without_agents_table = self.move_to_table_and_get_data(
            "UDP - internal connection details from internal devices without agents")
        tcp_internal_to_internal_devices_without_agents_table = self.move_to_table_and_get_data(
            "TCP - internal connection to internal devices without agents")
        udp_internal_to_internal_devices_without_agents_table = self.move_to_table_and_get_data(
            "UDP - internal connection to internal devices without agents")
        tcp_external_server_connection_details_table = self.move_to_table_and_get_data(
            "TCP - external server connection details")
        upd_external_server_connection_details_table = self.move_to_table_and_get_data(
            "UDP - external server connection details")
        info(f"{alerts_table=}\n{unique_process_details_table=}\n{list_of_applications_table=}\n"
             f"{exposed_ports_table=}\n{executable_versions_table=}\n{command_line_by_executable_table=}\n"
             f"{applications_information_table=}\n{tcp_external_table=}\n{udp_external_table=}\n{tcp_internal_table=}\n"
             f"{udp_internal_table=}\n{tcp_internal_from_internal_devices_without_agents_table=}\n"
             f"{upd_internal_from_internal_devices_without_agents_table=}\n"
             f"{tcp_internal_to_internal_devices_without_agents_table=}\n"
             f"{udp_internal_to_internal_devices_without_agents_table=}\n"
             f"{tcp_external_server_connection_details_table=}\n{upd_external_server_connection_details_table=}")

        info("7. Users")
        self.click_tab("Users")
        alerts_table = self.move_to_table_and_get_data("Alerts", move_down=True)
        user_properties_table = self.move_to_table_and_get_data("User properties")
        user_login_activity_table = self.move_to_table_and_get_data("User login activity")
        user_authentication_summary_table = self.move_to_table_and_get_data("User authentication summary")
        machine_properties_table = self.move_to_table_and_get_data("Machine properties")
        user_root_action_table = self.move_to_table_and_get_data("User root action")
        info(f"{alerts_table=}\n{user_properties_table=}\n{user_login_activity_table=}\n"
             f"{user_authentication_summary_table=}\n{machine_properties_table=}\n{user_root_action_table=}")
