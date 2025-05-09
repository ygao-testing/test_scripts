import json
import logging
import time

from datetime import datetime, timedelta
from copy import deepcopy
from typing import Any, Dict
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


class HostVulnerabilitiesHelper:
    def __init__(self, user_api, agent_deployment_timestamp: datetime = datetime.now()):
        self.user_api = user_api
        start_date = agent_deployment_timestamp - timedelta(hours=7)
        end_date = agent_deployment_timestamp + timedelta(hours=7)
        self.payload_template: Dict[str, Any] = {
            "ParamInfo": {
                "StartTimeRange": int(start_date.timestamp() * 1000.0),
                "EndTimeRange": int(end_date.timestamp() * 1000.0),
                "EnableEvalDetailsMView": True
            },
        }

    def list_all_vulnerability_hosts(self) -> list:
        """Helper function to list all hosts inside vulnerability page"""
        logger.debug("list_all_vulnerability_hosts()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="HostVuln_HostsSummaryAll_MV_NamedSet", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"All vulnerability hosts: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_all_cve_scanned(self) -> list:
        """Helper function to list all scanned CVEs"""
        logger.debug("list_all_cve_scanned()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="HostVuln_LastEvalSummaryAllByCVE", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"All vulnerability cves: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_cve_details(self, cve_id: str) -> list:
        """
        Helper function to fetch detail information about a CVE according to ID
        :param cve_id: ID of the CVE, e.g CVE-2021-44228

        :return: CVE info
        """
        logger.debug(f"fetch_cve_details(), {cve_id}")
        payload = deepcopy(self.payload_template)
        payload['ParamInfo']['VULN_ID'] = cve_id
        payload['Filters'] = {
            "HostVuln_Filters.VULN_ID": [
                {
                    "value": cve_id,
                    "filterGroup": "include"
                }
            ]
        }
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="HostVuln_LastEvalSummaryAllByCVE_Details", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"{cve_id} details: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_host_associate_to_cve(self, cve_id: str) -> list:
        """
        Helper function to fetch vulnerable hosts associate with a CVE
        :param cve_id: ID of the CVE, e.g. CVE-2021-44228

        :return: List of hosts info
        """
        logger.debug(f"fetch_host_associate_to_cve(), {cve_id}")
        payload = deepcopy(self.payload_template)
        cve_info = self.fetch_cve_details(cve_id)
        if not cve_info:
            logger.error(f"No {cve_id} found")
            raise Exception(f"No {cve_id} found")
        package_name, version_installed = cve_info[0]['PACKAGE_TAGS']['name'], cve_info[0]['PACKAGE_TAGS']['version_installed']
        payload['ParamInfo']['VULN_ID'] = cve_id
        payload['ParamInfo']['VERSION_INSTALLED'] = version_installed
        payload['ParamInfo']['PACKAGE'] = package_name
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="HostVuln_HostsByCVEPackage", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Hosts associate with {cve_id}: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_host_vulnerability_by_host_name(self, hostname: str) -> dict | None:
        """
        Helper function to fetch detail vulnerability and host info by hostname

        :param hostname: Hostname
        :return: Dictionary contains all info about the host, and its vulnerabilities
        """
        logger.debug(f"fetch_host_vulnerability_by_host_name() for {hostname}")
        all_hosts = self.list_all_vulnerability_hosts()
        for host in all_hosts:
            if host['HOST_NAME'] == hostname:
                logger.debug(f"{hostname} info: {host}")
                return host
        logger.debug(f"Found no host with hostname = {hostname}")
        return None

    def fetch_host_vulnerability_by_instance_id(self, instance_id: str) -> dict:
        """
        Helper function to fetch detail vulnerability and host info by instance_id

        :param instance_id: Instance ID
        :return: Dictionary contains all info about the host, and its vulnerabilities
        """
        logger.debug(f"fetch_host_vulnerability_by_instance_id() for {instance_id}")
        all_hosts = self.list_all_vulnerability_hosts()
        for host in all_hosts:
            if host.get('MACHINE_TAGS', {}).get('InstanceId') == instance_id:
                logger.debug(f"{instance_id} info: {host}")
                return host
        logger.debug(f"Found no host with instance_id = {instance_id}")
        raise Exception(f"Found no host with instance_id = {instance_id}")

    def fetch_host_vulnerable_packages_by_hostname(self, hostname: str) -> list:
        """
        Helper function to fetch detail vulnerable packages by hostname

        :param hostname: Hostname
        :return: A list of dictionary contains all info about all vulnerable packages for a host
        """
        logger.debug(f"fetch_host_vulnerable_packages_by_hostname() for {hostname}")
        host_info = self.fetch_host_vulnerability_by_host_name(hostname)
        if not host_info:
            logger.debug(f"Not found host with hostname = {hostname}")
        mid = host_info['MID'] if host_info else ""
        eval_guid = host_info['EVAL_GUID'] if host_info else ""
        payload = deepcopy(self.payload_template)
        payload['ParamInfo']['MID'] = mid
        payload['ParamInfo']['EVAL_GUID'] = eval_guid
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="HostVuln_VulnDetailsByEvalGuid_ByPackage", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"All vulnerable packages for {hostname}: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_host_vulnerable_packages_by_instance_id(self, instance_id: str) -> list:
        """
        Helper function to fetch detail vulnerable packages by instance_id

        :param instance_id: Instance ID
        :return: A list of dictionary contains all info about all vulnerable packages for a host
        """
        logger.debug(f"fetch_host_vulnerable_packages_by_instance_id() for {instance_id}")
        host_info = self.fetch_host_vulnerability_by_instance_id(instance_id)
        if not host_info:
            logger.debug(f"Not found host with instance id = {instance_id}")
            raise Exception(f"Not found host with instance id = {instance_id}")
        mid = host_info['MID'] if host_info else ""
        eval_guid = host_info['EVAL_GUID'] if host_info else ""
        payload = deepcopy(self.payload_template)
        payload['ParamInfo'].pop("EnableEvalDetailsMView")
        payload['ParamInfo']['MID'] = mid
        payload['ParamInfo']['EVAL_GUID'] = eval_guid
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="HostVuln_VulnDetailsByEvalGuid_ByPackage", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"All vulnerable packages for {instance_id}: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def get_vuln_cve_trend_by_instance_id(self, instance_id: str) -> list:
        """Test case for Host vulnerability page using different filter using v1 query card HostVuln_StatsSummaryCVETrend

        Given: Filters payloads generated from fixtures, and different query card
        When: Query Card V1 API will be called to execute the given query card
        Then: API response should return a 200 status code.

        Args:
            instance_id: AWS isntance ID
        """
        query_card_api = QueryCard(self.user_api)
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            "HostVuln_Filters.MACHINE_TAGS": [
                {
                    "filterGroup": "include",
                    "value": f"InstanceId->{instance_id}"
                }
            ]
        }
        query_card_response = query_card_api.exec_query_card(card_name="HostVuln_StatsSummaryCVETrend", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"CVE trend for {instance_id}: {query_card_response.json()}")
        return query_card_response.json()['data']

    def get_vuln_host_summary_by_instance_id(self, instance_id: str) -> list:
        """Test case for Host vulnerability page using different filter using v1 query card HostVuln_HostsSummaryAll_MV_NamedSet

        Given: Filters payloads generated from fixtures, and different query card
        When: Query Card V1 API will be called to execute the given query card
        Then: API response should return a 200 status code.

        Args:
            instance_id: AWS isntance ID
        """
        query_card_api = QueryCard(self.user_api)
        payload = deepcopy(self.payload_template)
        payload['Filters'] = {
            "HostVuln_Filters.MACHINE_TAGS": [
                {
                    "filterGroup": "include",
                    "value": f"InstanceId->{instance_id}"
                }
            ]
        }
        query_card_response = query_card_api.exec_query_card(card_name="HostVuln_HostsSummaryAll_MV_NamedSet", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Host summary for {instance_id}: {query_card_response.json()}")
        return query_card_response.json()['data']

    def wait_until_instance_has_cve_trend(self, instance_id, wait_until: int):
        """Wait for agent host to be returned by vulnerability query card HostVuln_StatsSummaryCVETrend."""
        logger.debug(f'Wait until {instance_id} has cve trend')
        agent_found = False
        first_try = True
        vuln_stats = []
        while first_try or (time.monotonic() < wait_until and not agent_found):
            if not first_try:
                time.sleep(240)
            first_try = False
            vuln_stats = self.get_vuln_cve_trend_by_instance_id(instance_id)
            if type(vuln_stats) is list and len(vuln_stats) == 1:
                logger.debug(f'Found agent host {instance_id} in {vuln_stats}')
                agent_found = True
        if not agent_found:
            raise TimeoutError(
                f'Agent host {instance_id} was not returned by Vulnerability dashboard APIs.'
                f'Current time {datetime.now()}'
                f'Last API response: {vuln_stats}.'
            )

    def wait_until_instance_has_vuln_host_summary(self, instance_id, wait_until: int):
        """Wait for agent host to be returned by vulnerability query card 'HostVuln_HostsSummaryAll_MV_NamedSet'."""
        logger.debug(f'Wait until {instance_id} has vulnerability host summary')
        agent_found = False
        first_try = True
        vuln_stats = []
        while first_try or (time.monotonic() < wait_until and not agent_found):
            if not first_try:
                time.sleep(240)
            first_try = False
            vuln_stats = self.get_vuln_host_summary_by_instance_id(instance_id)
            if type(vuln_stats) is list and len(vuln_stats) == 1:
                logger.debug(f'Found agent host {instance_id} in {vuln_stats}')
                agent_found = True
        if not agent_found:
            raise TimeoutError(
                f'Agent host {instance_id} was not returned by Vulnerability dashboard APIs.'
                f'Current time {datetime.now()}'
                f'Last API response: {vuln_stats}.'
            )

    def wait_until_instance_has_vulnerability(self, instance_id, wait_until: int):
        """Wait for agent host to have more than 0 vulnerabilities."""
        vuln_found = False
        first_try = True
        vuln_stats = []
        total_vuln = None
        vuln_data_returned = False
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and not vuln_data_returned):
            if not first_try:
                time.sleep(240)
            first_try = False
            vuln_stats = self.get_vuln_host_summary_by_instance_id(instance_id)
            if type(vuln_stats) is list and len(vuln_stats) == 1:
                vuln_data_returned = True
                total_vuln = int(vuln_stats[0]['NUM_VULNERABILITIES'])
                if total_vuln > 0:
                    logger.debug(f'Found {total_vuln} vulnerabilities for agent host {instance_id}')
                    vuln_found = True
                    time_passed = int(time.monotonic() - start_time)
                    logger.debug(f"Host {instance_id} was found vulnerable after {time_passed} secs, current time is {datetime.now()}")
        if not vuln_data_returned:
            raise TimeoutError(
                f'Agent host {instance_id} has no vulnerability summary returned.'
                f'Current time {datetime.now()}'
                f'Last API response: {vuln_stats}.'
            )
        elif not vuln_found:
            raise TimeoutError(
                f'Agent host {instance_id} has 0 vulnerabilities.'
                f'Current time {datetime.now()}'
                f'Last API response: {vuln_stats}.'
            )

    def wait_until_instance_change_to_agent_and_agentless_coverage_type(self, instance_id: str, wait_until: int):
        """Wait for agent host changes to agent and agentless scanning type"""
        logger.debug(f'Wait until {instance_id} changes to agent and agentless scanning type')
        coverage_type_changed = False
        first_try = True
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and not coverage_type_changed):
            if not first_try:
                time.sleep(240)
            first_try = False
            host_info = self.fetch_host_vulnerability_by_instance_id(instance_id=instance_id)
            coverage_type = host_info.get("COVERAGE_TYPES")
            if coverage_type == "Agent and Agentless":
                coverage_type_changed = True
                time_passed = int(time.monotonic() - start_time)
                logger.debug(f"Host {instance_id} was covered by both Agent and Agentless after {time_passed} secs, current time is {datetime.now()}")
                break
        if not coverage_type_changed:
            raise TimeoutError(
                f'Agent host {instance_id} was not changed to Agent and Agentless scanned'
                f'Current time {datetime.now()}'
                f'Last API response: {host_info}.'
            )

    def wait_until_package_appears_for_host(self, package_name: str, instance_id: str, wait_until: int):
        """Wait for agent host has a specific package scanned"""
        logger.debug(f'Wait until {package_name} scanned for {instance_id}')
        found_package = False
        first_try = True
        start_time = time.monotonic()
        while first_try or (time.monotonic() < wait_until and not found_package):
            if not first_try:
                time.sleep(240)
            first_try = False
            packages = self.fetch_host_vulnerable_packages_by_instance_id(instance_id=instance_id)
            for package in packages:
                if package['PACKAGE_NAME'] == package_name:
                    found_package = True
                    time_passed = int(time.monotonic() - start_time)
                    logger.debug(f"Host {instance_id} was found {package_name} after {time_passed} secs")
                    break
        if not found_package:
            raise TimeoutError(
                f'{package_name} did not appear for agent host {instance_id}'
                f'Current time {datetime.now()}'
                f'Last API response: {packages}.'
            )

    def wait_until_package_active_for_host(self, package_name: str, instance_id: str, wait_until: int):
        """Wait for agent host has a specific package scanned and with status Active"""
        logger.debug(f'Wait until {package_name} active for {instance_id}')
        package_active = False
        first_try = True
        while first_try or (time.monotonic() < wait_until and not package_active):
            if not first_try:
                time.sleep(240)
            first_try = False
            packages = self.fetch_host_vulnerable_packages_by_instance_id(instance_id=instance_id)
            for package in packages:
                if package['PACKAGE_NAME'] == package_name and package['PACKAGE_STATUS'] == "ACTIVE":
                    package_active = True
                    break
        if not package_active:
            raise TimeoutError(
                f'{package_name} did not change to Active for agent host {instance_id}'
                f'Current time {datetime.now()}'
                f'Last API response: {packages}.'
            )
