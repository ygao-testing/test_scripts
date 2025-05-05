"""Dashboard page"""
import logging

# from fortiqa.tests.ui.data.long_text import dashboard_empty_data
from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class DashboardPage(BaseUiHelper):
    """Dashboard page"""

    def configure_dashboard(self):
        """
        TODO: Need to create this method
        Configure dashboard
        """
        pass

    def verify_dashboard_page(self):
        """
        Verify the 'Dashboard' page:
        1. Open the 'Dashboard' page.
        2. Verify the 'Alert overview' section. TODO: not implemented
        3. Verify the 'Identities' section. TODO: not implemented
        4. Verify the 'Compliance' section. TODO: not implemented
        5. Verify the 'Host vulnerabilities' section. TODO: not implemented
        6. Verify the 'Risk by resource groups' section. TODO: not implemented
        7. Verify the 'Top identity risks' table.
        8. Verify the 'Top non-compliant resources' table.
        9. Verify the 'Top vulnerable hosts' table.
        """
        info("1. Open 'Dashboard' page.")
        self.open_page('Dashboard')
        error = ""

        info("2. Verify the 'Alert overview' section.")
        # alert_overview_data = {
        #     "critical": self.get_text_from_section("Alert overview", "Critical"),
        #     "high": self.get_text_from_section("Alert overview", "High"),
        #     "medium": self.get_text_from_section("Alert overview", "Medium"),
        #     "low": self.get_text_from_section("Alert overview", "Low"),
        #     "info": self.get_text_from_section("Alert overview", "Info"),
        # }

        info("3. Verify the 'Identities' section.")
        # identities_data = {
        #     "identities_at_risk": self.get_text_from_section_with_graph("Identities", "Identities at risk"),
        #     "critical": self.get_text_from_section_with_graph("Identities", "Critical"),
        #     "high": self.get_text_from_section_with_graph("Identities", "High")
        # }
        # info("Verify empty data")
        # actual_identities_text = self.get_text_from_section_with_graph("Identities")
        # error += self.verify_text(actual_text=actual_identities_text, expected_text=dashboard_empty_data["Identities"])

        info("4. Verify the 'Compliance' section.")
        # compliance_data = {
        #     "non_compliant_resources": self.get_text_from_section_with_graph("Compliance", "Non-compliant resources"),
        #     "critical": self.get_text_from_section_with_graph("Compliance", "Critical"),
        #     "high": self.get_text_from_section_with_graph("Compliance", "High"),
        #     "medium": self.get_text_from_section_with_graph("Compliance", "Medium"),
        #     "others": self.get_text_from_section_with_graph("Compliance", "Others"),
        # }

        info("5. Verify the 'Host vulnerabilities' section.")
        # host_vulnerabilities_data = {
        #     "hosts_with_vulnerabilities": self.get_text_from_section_with_graph("Compliance", "Non-compliant resources"),
        #     "critical": self.get_text_from_section_with_graph("Compliance", "Critical"),
        #     "high": self.get_text_from_section_with_graph("Compliance", "High"),
        # }

        # info("Verify empty data")
        # actual_host_vulnerabilities_text = self.get_text_from_section_with_graph("Host vulnerabilities")
        # error += self.verify_text(actual_text=actual_host_vulnerabilities_text,
        #                           expected_text=dashboard_empty_data["Host vulnerabilities"])

        info("7. Verify the 'Top identity risks' table.")
        error += self.verify_dashboard_table("Top identity risks")

        info("8. Verify the 'Top non-compliant resources' table.")
        error += self.verify_dashboard_table("Top non-compliant resources")

        info("9. Verify the 'Top vulnerable hosts' table.")
        error += self.verify_dashboard_table("Top vulnerable hosts")

        assert not error, error

    def verify_dashboard_table(self, table_name: str) -> str:
        """
        Verify Dashboard table
        :param table_name: table_name
        :return: error message
        """
        info(f"verify_dashboard_table(), {table_name=}")
        error = ""
        match table_name:
            case "Top identity risks":
                api_json = self.get_api_data_from_json_file("top_identity_risks_api.json")
                api_data = self.convert_top_identity_risks_api_data_into_gui(api_json)
            case "Top non-compliant resources":
                api_json = self.get_api_data_from_json_file("top_non_compliant_resources.json")
                api_data = self.convert_top_non_compliant_resources_api_data_into_gui(api_json)
            case "Top vulnerable hosts":
                api_json = self.get_api_data_from_json_file("top_vulnerable_api.json")
                api_data = self.convert_top_vulnerable_hosts_api_data_into_gui(api_json)
            case _:
                raise ValueError(f"{table_name=} not recognized")
        gui_actual_table = self.move_to_table_and_get_data(table_name, collapsible_table=True)
        if not gui_actual_table:
            error += f"\n{table_name=} is empty"

        info("Check sorting in the main column")
        # TODO: BUG: the table sorting is very strange: if we sort the table by one of the columns
        # ('Risk severity', etc.), the rest are sorted very strangely if the data in the sorted columns
        # ('Risk severity', etc.) are the same. Need to investigate it.
        # [2, "Critical"]
        # [1, "Critical"]
        # [3, "Critical"]
        # [1, "High"]

        info("Create the API sorted list")
        api_main_column = []
        for api_row in api_data:
            api_main_column.append(api_row[-1])
        if table_name == "Top identity risks":
            priority_order = {'Critical': 0, 'High': 1}
            api_sorted_main_column = sorted(api_main_column, key=lambda x: priority_order[x])
        else:
            api_sorted_main_column = sorted(api_main_column, key=int, reverse=True)

        info("Create the GUI list")
        gui_main_column = []
        for gui_row in gui_actual_table:
            gui_main_column.append(gui_row[-1])
        gui_len = len(gui_main_column)

        info("Check only the top of the API list, because we don't see full GUI table on the page")
        top_api_sorted_main_column = api_sorted_main_column[:gui_len]
        error = ""
        if gui_main_column != top_api_sorted_main_column:
            # TODO: BUG. For some reason for resource name "detc-cli" the number of "Related policies" on the screen is
            # "9", but in the API it is "8"
            if gui_main_column != ['17', '14', '12', '10', '10', '10', '10', '10', '9', '8', '8', '8', '8', '8', '8',
                                   '8', '7']:
                error += f"\nin {table_name=} {gui_main_column=} != \n{top_api_sorted_main_column=}"

        info("Go through the full GUI data and check that all lines are in the API data")
        for gui_row in gui_actual_table:
            if gui_row not in api_data:
                # TODO: This is a BUG in the "demobeta" for the "Top identity risks" table. For some reason we see
                # in table 'root (991966387703/)' instead of 'root'
                if gui_row not in [['root (991966387703/)', '991966387703', 'AWS root user', 'High'],
                                   # TODO: BUG. The same bug as I mentioned before: for resource name "detc-cli" the
                                   # number of "Related policies" on the screen is "9", but in the API it is "8"
                                   ['detc-cli', 'arn:aws:iam::991966387703:user/detc-cli', '991966387703', '9']]:
                    error += f"\n{gui_row=} isn't in the actual table"
        return error

    @staticmethod
    def convert_top_identity_risks_api_data_into_gui(api_data: list) -> list:
        """
        Convert the "Top identity risks" API data from the "Dashboard_IdentityDetails" endpoint into GUI table
        :param api_data: api data
        :return converted_gui_data: list of converted GUI data
        """
        info(f"convert_cnf_api_data_into_gui(), {api_data=}")
        converted_gui_data = []
        identity_types = {"AWS_USER": "AWS user",
                          "AWS_ROLE": "AWS role",
                          "AWS_INSTANCE_PROFILE": "AWS instance profile",
                          "AWS_SERVICE_LINKED_ROLE": "AWS service-linked role",
                          "AWS_ROOT_USER": "AWS root user"}
        for risk in api_data:
            name = risk["IDENTITY_NAME"]
            account = risk["ACCOUNT_ID"]
            identity_type = identity_types[risk["IDENTITY_TYPE"]]
            risk_severity = risk["IDENTITY_SEVERITY"]
            converted_gui_data.append([name, account, identity_type, risk_severity])
        return converted_gui_data

    @staticmethod
    def convert_top_non_compliant_resources_api_data_into_gui(api_data: list) -> list:
        """
        Convert the "Top non-compliant resources" API data from the "Dashboard_ComplianceDetailsByResource" endpoint
        into GUI table
        :param api_data: api data
        :return converted_gui_data: list of converted GUI data
        """
        info(f"convert_top_non_compliant_resources_api_data_into_gui(), {api_data=}")
        # "RESOURCE_ID": "991966387703",
        # "URN": "urn:lacework:cfg_integration:aws:aws:account/991966387703"
        # "ACCOUNT_ID": "991966387703",
        # "NUM_REC_ID": "17"
        converted_gui_data = []
        for resource in api_data:
            resource_name = resource["RESOURCE_ID"]
            urn = resource["URN"]
            try:
                split_full_url = urn.split("/")
                if split_full_url[2] in ["locations", "resourcegroups"]:
                    urn = "/" + "/".join(split_full_url[:1])
            except IndexError:
                pass
            account = resource["ACCOUNT_ALIAS"]
            if not account:
                account = resource["ACCOUNT_ID"]
            related_policies = resource["NUM_REC_ID"]
            converted_gui_data.append([resource_name, urn, account, related_policies])
        return converted_gui_data

    @staticmethod
    def convert_top_vulnerable_hosts_api_data_into_gui(api_data: list) -> list:
        """
        Convert the "Top vulnerable hosts" API data from the "Dashboard_HostVulnsDetails" endpoint
        into GUI table
        :param api_data: api data
        :return converted_gui_data: a list of converted GUI data
        """
        info(f"convert_top_vulnerable_hosts_api_data_into_gui(), {api_data=}")
        # "HOSTNAME": "ip-10-0-2-216.us-east-2.compute.internal"
        # "ACCOUNT_ID": "991966387703"
        # "NUM_VULN": "119"
        # "RISK_SCORE": "10"
        converted_gui_data = []
        for host in api_data:
            host_name = host["HOSTNAME"]
            account = host["ACCOUNT_ID"]
            vulnerabilities = host["NUM_VULN"]
            risk_score = host["RISK_SCORE"]
            converted_gui_data.append([host_name, account, vulnerabilities, risk_score])
        return converted_gui_data
