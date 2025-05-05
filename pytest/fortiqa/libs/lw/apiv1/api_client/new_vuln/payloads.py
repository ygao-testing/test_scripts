from dataclasses import dataclass, field
from enum import Enum
from typing import List, Union, Dict


class ComparisonOperator(Enum):
    IS_IN = "in"
    IS_EQUAL_TO = "eq"
    IS_ANY_OF = "in"
    IS_NOT_ANY_OF = "not_in"
    IS_NOT_EQUAL_TO = "ne"
    IS_LESS_THAN = "lt"
    IS_LESS_THAN_OR_EQUAL_TO = "le"
    IS_GREATER_THAN = "gt"
    IS_GREATER_THAN_OR_EQUAL_TO = "ge"
    STARTS_WITH = "startsWith"
    ENDS_WITH = "endsWith"
    CONTAINS = "contains"


class HostFilter:
    PREFIX = "VulnPres_HostFilters."
    HOST_NAME = PREFIX + "HOST_NAME"
    MACHINE_STATUS = PREFIX + "MACHINE_STATUS"  # Offline: "0", Launched: "1" and Online: "2"
    INTERNET_EXPOSED = PREFIX + "INTERNET_EXPOSED"
    ACCOUNT_ID = PREFIX + "ACCOUNT_ID"
    ACCOUNT_ALIAS = PREFIX + "ACCOUNT_ALIAS"
    ORGANIZATION_ID = PREFIX + "ORGANIZATION_ID"
    AGENT_LAST_DISCOVERED_TIME = PREFIX + "AGENT_LAST_DISCOVERED_TIME"
    AGENTLESS_LAST_DISCOVERED_TIME = PREFIX + "AGENTLESS_LAST_DISCOVERED_TIME"
    AVD_ENABLED = PREFIX + "AVD_ENABLED"
    COVERAGE_TYPE = PREFIX + "COVERAGE_TYPE"
    EXTERNAL_IP = PREFIX + "EXTERNAL_IP"
    INTERNAL_IP = PREFIX + "INTERNAL_IP"
    INTERNET_EXPOSED_LAST_UPDATED = PREFIX + "INTERNET_EXPOSED_LAST_UPDATED"
    LAST_EVAL_TIME = PREFIX + "LAST_EVAL_TIME"
    MACHINE_TAGS = PREFIX + "MACHINE_TAGS"
    MACHINE_ID = PREFIX + "MACHINE_ID"
    OS_EOL_DATE = PREFIX + "OS_EOL_DATE"
    OS_NAME = PREFIX + "OS_NAME"
    OS_NAMESPACE = PREFIX + "OS_NAMESPACE"
    OS_OUT_OF_DATE = PREFIX + "OS_OUT_OF_DATE"
    OS_REBOOT_REQUIRED = PREFIX + "OS_REBOOT_REQUIRED"
    OS_TYPE = PREFIX + "OS_TYPE"
    OS_UPDATES_DISABLED = PREFIX + "OS_UPDATES_DISABLED"
    OS_VERSION = PREFIX + "OS_VERSION"
    PUBLIC_FACING = PREFIX + "PUBLIC_FACING"
    HOST_RISK_SCORE = PREFIX + "HOST_RISK_SCORE"
    ZONE = PREFIX + "ZONE"
    HOST_FIRST_DISCOVERED_TIME = PREFIX + "HOST_FIRST_DISCOVERED_TIME"
    HOST_LAST_DISCOVERED_TIME = PREFIX + "HOST_LAST_DISCOVERED_TIME"
    MACHINE_IMAGE = PREFIX + "MACHINE_IMAGE"
    FIXABLE = PREFIX + "FIXABLE"


class VulnFilter:
    PREFIX = "VulnPres_VulnFilters."
    VULN_ID = PREFIX + "VULN_ID"
    SEVERITY = PREFIX + "SEVERITY"
    VULN_RISK_SCORE = PREFIX + "VULN_RISK_SCORE"
    DESCRIPTION = PREFIX + "DESCRIPTION"
    PUBLIC_EXPLOIT_AVAILABLE = PREFIX + "PUBLIC_EXPLOIT_AVAILABLE"
    PUBLIC_EXPLOIT_DATE = PREFIX + "PUBLIC_EXPLOIT_DATE"
    VULN_FIRST_DISCOVERED_TIME = PREFIX + "VULN_FIRST_DISCOVERED_TIME"
    VULN_LAST_DISCOVERED_TIME = PREFIX + "VULN_LAST_DISCOVERED_TIME"
    CVSS_ATTACK_COMPLEXITY = PREFIX + "CVSS_ATTACK_COMPLEXITY"
    CVSS_ATTACK_VECTOR = PREFIX + "CVSS_ATTACK_VECTOR"
    CVSS_AUTHENTICATION = PREFIX + "CVSS_AUTHENTICATION"
    CVSS_AVAILABILITY = PREFIX + "CVSS_AVAILABILITY"
    CVSS_CONFIDENTIALITY = PREFIX + "CVSS_CONFIDENTIALITY"
    CVSS_EXPLOITABILITY_SCORE = PREFIX + "CVSS_EXPLOITABILITY_SCORE"
    CVSS_IMPACT_SCORE = PREFIX + "CVSS_IMPACT_SCORE"
    CVSS_INTEGRITY = PREFIX + "CVSS_INTEGRITY"
    CVSS_PRIVILEGES_REQUIRED = PREFIX + "CVSS_PRIVILEGES_REQUIRED"
    CVSS_SCOPE = PREFIX + "CVSS_SCOPE"
    CVSS_SCORE = PREFIX + "CVSS_SCORE"
    CVSS_USER_INTERACTION = PREFIX + "CVSS_USER_INTERACTION"
    CVSS_VECTOR_STRING = PREFIX + "CVSS_VECTOR_STRING"
    CVSS_VERSION = PREFIX + "CVSS_VERSION"
    PACKAGE_RISK_SCORE = "PACKAGE_RISK_SCORE"


class ImageFilter:
    PREFIX = "VulnPres_ImageFilters."
    IMAGE_NAMES = PREFIX + "IMAGE_NAMES"
    IMAGE_ID = PREFIX + "IMAGE_ID"
    DIGESTS = PREFIX + "DIGESTS"
    IMAGE_REGISTRIES = PREFIX + "IMAGE_REGISTRIES"
    IMAGE_REPOSITORIES = PREFIX + "IMAGE_REPOSITORIES"
    HAS_ACTIVE_CONTAINERS = PREFIX + "HAS_ACTIVE_CONTAINERS"
    HAS_AVD_ENABLED_CONTAINERS = PREFIX + "HAS_AVD_ENABLED_CONTAINERS"
    SCAN_STATUS = PREFIX + "SCAN_STATUS"
    IMAGE_TYPE = PREFIX + "IMAGE_TYPE"
    INTERNET_EXPOSED = PREFIX + "INTERNET_EXPOSED"
    INTERNET_EXPOSED_LAST_UPDATED = PREFIX + "INTERNET_EXPOSED_LAST_UPDATED"
    LAST_SCAN_TIME = PREFIX + "LAST_SCAN_TIME"
    LATEST_SCAN_SUCCESSFUL = PREFIX + "LATEST_SCAN_SUCCESSFUL"
    LATEST_SUCCESSFUL_SCAN_TIME = PREFIX + "LATEST_SUCCESSFUL_SCAN_TIME"
    OS = PREFIX + "OS"
    REQUEST_SOURCES = PREFIX + "REQUEST_SOURCES"
    IMAGE_RISK_SCORE = PREFIX + "IMAGE_RISK_SCORE"
    IMAGE_CREATED_TIME = PREFIX + "IMAGE_CREATED_TIME"
    IMAGE_SIZE = PREFIX + "IMAGE_SIZE"
    SCAN_ERROR_MESSAGE = PREFIX + "SCAN_ERROR_MESSAGE"
    IMAGE_TAGS = PREFIX + "IMAGE_TAGS"
    ACTIVE_CONTAINER_COUNT = PREFIX + "ACTIVE_CONTAINER_COUNT"
    IMAGE_FIRST_ACTIVE_TIME = PREFIX + "IMAGE_FIRST_ACTIVE_TIME"
    IMAGE_LAST_ACTIVE_TIME = PREFIX + "IMAGE_LAST_ACTIVE_TIME"
    ACCOUNT_ID = PREFIX + "ACCOUNT_ID"


class PackageFilter:
    PREFIX = "VulnPres_PackageFilters."
    PACKAGE_NAME = PREFIX + "PACKAGE_NAME"
    PACKAGE_NAMESPACE = PREFIX + "PACKAGE_NAMESPACE"
    PACKAGE_RISK_SCORE = PREFIX + "PACKAGE_RISK_SCORE"
    PACKAGE_VERSION = PREFIX + "PACKAGE_VERSION"


class VulnObservationFilters:
    PREFIX = "VulnPres_VulnObservationFilters."
    FIX_VERSION = PREFIX + "FIX_VERSION"
    PACKAGE_LAST_ACTIVE_TIME = PREFIX + "PACKAGE_LAST_ACTIVE_TIME"
    STATUS_CATEGORY = PREFIX + "STATUS_CATEGORY"
    STATUS = PREFIX + "STATUS"
    PACKAGE_PATH = PREFIX + "PACKAGE_PATH"
    PACKAGE_STATUS = PREFIX + "PACKAGE_STATUS"
    VULNERABLE_SINCE_TIME = PREFIX + "VULNERABLE_SINCE_TIME"
    FIXED_TIME = PREFIX + "FIXED_TIME"
    FIXABLE = PREFIX + "FIXABLE"
    ENTITY_STATUS_CATEGORY = "ENTITY_STATUS_CATEGORY"
    ENTITY_TYPE = PREFIX + "ENTITY_TYPE"
    FIRST_DISCOVERED_TIME = PREFIX + "FIRST_DISCOVERED_TIME"
    LAST_DISCOVERED_TIME = PREFIX + "LAST_DISCOVERED_TIME"


class TotalVulnFilter:
    VULN_COUNT_CRITICAL = "VULN_COUNT_CRITICAL"
    VULN_COUNT_CRITICAL_FIXABLE = "VULN_COUNT_CRITICAL_FIXABLE"
    VULN_COUNT_HIGH = "VULN_COUNT_HIGH"
    VULN_COUNT_HIGH_FIXABLE = "VULN_COUNT_HIGH_FIXABLE"
    VULN_COUNT_INFO = "VULN_COUNT_INFO"
    VULN_COUNT_INFO_FIXABLE = "VULN_COUNT_INFO_FIXABLE"
    VULN_COUNT_LOW = "VULN_COUNT_LOW"
    VULN_COUNT_LOW_FIXABLE = "VULN_COUNT_LOW_FIXABLE"
    VULN_COUNT_MEDIUM = "VULN_COUNT_MEDIUM"
    VULN_COUNT_MEDIUM_FIXABLE = "VULN_COUNT_MEDIUM_FIXABLE"
    VULN_COUNT_TOTAL = "VULN_COUNT_TOTAL"
    VULN_COUNT_TOTAL_FIXABLE = "VULN_COUNT_TOTAL_FIXABLE"
    ENTITY_COUNT_TOTAL_VULNERABLE = "ENTITY_COUNT_TOTAL_VULNERABLE"


class TotalPackageFilter:
    PACKAGE_COUNT_EXCEPTION = "PACKAGE_COUNT_EXCEPTION"
    PACKAGE_COUNT_NOT_VULNERABLE = "PACKAGE_COUNT_NOT_VULNERABLE"
    PACKAGE_COUNT_VULNERABLE = "PACKAGE_COUNT_VULNERABLE"


class TotalHostFilter:
    HOST_COUNT_VULNERABLE = "HOST_COUNT_VULNERABLE"
    HOST_COUNT_EXCEPTION = "HOST_COUNT_EXCEPTION"
    HOST_COUNT_NOT_VULNERABLE = "HOST_COUNT_NOT_VULNERABLE"
    HOST_COUNT_AVD_ENABLED = "HOST_COUNT_AVD_ENABLED"
    HOST_COUNT_INTERNET_EXPOSED = "HOST_COUNT_INTERNET_EXPOSED"


class TotalImageFilter:
    IMAGE_COUNT_VULNERABLE = "IMAGE_COUNT_VULNERABLE"
    IMAGE_COUNT_EXCEPTION = "IMAGE_COUNT_EXCEPTION"
    IMAGE_COUNT_NOT_VULNERABLE = "IMAGE_COUNT_NOT_VULNERABLE"


class TotalEntityFilter:
    ENTITY_COUNT_INTERNET_EXPOSED = "ENTITY_COUNT_INTERNET_EXPOSED"
    ENTITY_COUNT_AVD_ENABLED = "ENTITY_COUNT_AVD_ENABLED"


class HostReturnFields:
    account_alias = "ACCOUNT_ALIAS"
    account_id = "ACCOUNT_ID"
    agentless_last_discovered_time = "AGENTLESS_LAST_DISCOVERED_TIME"
    agent_last_discovered_time = "AGENT_LAST_DISCOVERED_TIME"
    avd_enabled = "AVD_ENABLED"
    avd_enabled_last_discovered_time = "AVD_ENABLED_LAST_DISCOVERED_TIME"
    cloud_provider = "CLOUD_PROVIDER"
    coverage_type = "COVERAGE_TYPE"
    entity_status_category = "ENTITY_STATUS_CATEGORY"
    entity_status_category_text = "ENTITY_STATUS_CATEGORY_TEXT"
    external_ip = "EXTERNAL_IP"
    first_discovered_time = "FIRST_DISCOVERED_TIME"
    host_name = "HOST_NAME"
    internal_ip = "INTERNAL_IP"
    internet_exposed = "INTERNET_EXPOSED"
    internet_exposed_last_updated = "INTERNET_EXPOSED_LAST_UPDATED"
    ip_props_last_discovered_time = "IP_PROPS_LAST_DISCOVERED_TIME"
    last_discovered_time = "LAST_DISCOVERED_TIME"
    last_eval_time = "LAST_EVAL_TIME"
    machine_id = "MACHINE_ID"
    machine_image = "MACHINE_IMAGE"
    machine_status = "MACHINE_STATUS"
    machine_status_last_discovered_time = "MACHINE_STATUS_LAST_DISCOVERED_TIME"
    machine_status_text = "MACHINE_STATUS_TEXT"
    machine_tags = "MACHINE_TAGS"
    mid = "MID"
    organization_id = "ORGANIZATION_ID"
    os_eol_date = "OS_EOL_DATE"
    os_eol_date_filterable = "OS_EOL_DATE_FILTERABLE"
    os_eol_date_last_discovered_time = "OS_EOL_DATE_LAST_DISCOVERED_TIME"
    os_name = "OS_NAME"
    os_namespace = "OS_NAMESPACE"
    os_out_of_date = "OS_OUT_OF_DATE"
    os_props_last_discovered_time = "OS_PROPS_LAST_DISCOVERED_TIME"
    os_reboot_required = "OS_REBOOT_REQUIRED"
    os_type = "OS_TYPE"
    os_updates_disabled = "OS_UPDATES_DISABLED"
    os_version = "OS_VERSION"
    package_count_exception = "PACKAGE_COUNT_EXCEPTION"
    package_count_not_vulnerable = "PACKAGE_COUNT_NOT_VULNERABLE"
    package_count_vulnerable = "PACKAGE_COUNT_VULNERABLE"
    public_facing = "PUBLIC_FACING"
    risk_info = "RISK_INFO"
    risk_score = "RISK_SCORE"
    risk_score_last_updated = "RISK_SCORE_LAST_UPDATED"
    status = "STATUS"
    status_text = "STATUS_TEXT"
    vuln_count_critical = "VULN_COUNT_CRITICAL"
    vuln_count_critical_fixable = "VULN_COUNT_CRITICAL_FIXABLE"
    vuln_count_high = "VULN_COUNT_HIGH"
    vuln_count_high_fixable = "VULN_COUNT_HIGH_FIXABLE"
    vuln_count_info = "VULN_COUNT_INFO"
    vuln_count_info_fixable = "VULN_COUNT_INFO_FIXABLE"
    vuln_count_low = "VULN_COUNT_LOW"
    vuln_count_low_fixable = "VULN_COUNT_LOW_FIXABLE"
    vuln_count_medium = "VULN_COUNT_MEDIUM"
    vuln_count_medium_fixable = "VULN_COUNT_MEDIUM_FIXABLE"
    vuln_count_total = "VULN_COUNT_TOTAL"
    vuln_count_total_fixable = "VULN_COUNT_TOTAL_FIXABLE"
    zone = "ZONE"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class PackageReturnFields:
    entity_count_avd_enabled = "ENTITY_COUNT_AVD_ENABLED"
    entity_count_internet_exposed = "ENTITY_COUNT_INTERNET_EXPOSED"
    entity_count_total_vulnerable = "ENTITY_COUNT_TOTAL_VULNERABLE"
    first_discovered_time = "FIRST_DISCOVERED_TIME"
    host_count_avd_enabled = "HOST_COUNT_AVD_ENABLED"
    host_count_exception = "HOST_COUNT_EXCEPTION"
    host_count_internet_exposed = "HOST_COUNT_INTERNET_EXPOSED"
    host_count_not_vulnerable = "HOST_COUNT_NOT_VULNERABLE"
    host_count_vulnerable = "HOST_COUNT_VULNERABLE"
    image_count_avd_enabled = "IMAGE_COUNT_AVD_ENABLED"
    image_count_exception = "IMAGE_COUNT_EXCEPTION"
    image_count_internet_exposed = "IMAGE_COUNT_INTERNET_EXPOSED"
    image_count_not_vulnerable = "IMAGE_COUNT_NOT_VULNERABLE"
    image_count_vulnerable = "IMAGE_COUNT_VULNERABLE"
    last_discovered_time = "LAST_DISCOVERED_TIME"
    package_name = "PACKAGE_NAME"
    package_namespaces = "PACKAGE_NAMESPACES"
    package_risk_info = "PACKAGE_RISK_INFO"
    package_risk_score = "PACKAGE_RISK_SCORE"
    package_risk_score_last_updated = "PACKAGE_RISK_SCORE_LAST_UPDATED"
    vuln_count_critical = "VULN_COUNT_CRITICAL"
    vuln_count_critical_fixable = "VULN_COUNT_CRITICAL_FIXABLE"
    vuln_count_high = "VULN_COUNT_HIGH"
    vuln_count_high_fixable = "VULN_COUNT_HIGH_FIXABLE"
    vuln_count_info = "VULN_COUNT_INFO"
    vuln_count_info_fixable = "VULN_COUNT_INFO_FIXABLE"
    vuln_count_low = "VULN_COUNT_LOW"
    vuln_count_low_fixable = "VULN_COUNT_LOW_FIXABLE"
    vuln_count_medium = "VULN_COUNT_MEDIUM"
    vuln_count_medium_fixable = "VULN_COUNT_MEDIUM_FIXABLE"
    vuln_count_total = "VULN_COUNT_TOTAL"
    vuln_count_total_fixable = "VULN_COUNT_TOTAL_FIXABLE"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class PackageReturnFieldsAssociateWithHost:
    entity_count_total_vulnerable = "ENTITY_COUNT_TOTAL_VULNERABLE"
    first_discovered_time = "FIRST_DISCOVERED_TIME"
    fix_version = "FIX_VERSION"
    host_count_exception = "HOST_COUNT_EXCEPTION"
    host_count_not_vulnerable = "HOST_COUNT_NOT_VULNERABLE"
    host_count_vulnerable = "HOST_COUNT_VULNERABLE"
    image_count_exception = "IMAGE_COUNT_EXCEPTION"
    image_count_not_vulnerable = "IMAGE_COUNT_NOT_VULNERABLE"
    image_count_vulnerable = "IMAGE_COUNT_VULNERABLE"
    last_discovered_time = "LAST_DISCOVERED_TIME"
    package_name = "PACKAGE_NAME"
    package_namespace = "PACKAGE_NAMESPACE"
    package_observation_digest = "PACKAGE_OBSERVATION_DIGEST"
    package_path = "PACKAGE_PATH"
    package_risk_info = "PACKAGE_RISK_INFO"
    package_risk_score = "PACKAGE_RISK_SCORE"
    package_risk_score_last_updated = "PACKAGE_RISK_SCORE_LAST_UPDATED"
    package_status = "PACKAGE_STATUS"
    package_status_text = "PACKAGE_STATUS_TEXT"
    package_version = "PACKAGE_VERSION"
    vuln_count_critical = "VULN_COUNT_CRITICAL"
    vuln_count_critical_fixable = "VULN_COUNT_CRITICAL_FIXABLE"
    vuln_count_high = "VULN_COUNT_HIGH"
    vuln_count_high_fixable = "VULN_COUNT_HIGH_FIXABLE"
    vuln_count_info = "VULN_COUNT_INFO"
    vuln_count_info_fixable = "VULN_COUNT_INFO_FIXABLE"
    vuln_count_low = "VULN_COUNT_LOW"
    vuln_count_low_fixable = "VULN_COUNT_LOW_FIXABLE"
    vuln_count_medium = "VULN_COUNT_MEDIUM"
    vuln_count_medium_fixable = "VULN_COUNT_MEDIUM_FIXABLE"
    vuln_count_total = "VULN_COUNT_TOTAL"
    vuln_count_total_fixable = "VULN_COUNT_TOTAL_FIXABLE"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class UniqueVulnByHostReturnFields:
    account_alias = "ACCOUNT_ALIAS"
    account_id = "ACCOUNT_ID"
    agentless_last_discovered_time = "AGENTLESS_LAST_DISCOVERED_TIME"
    agent_last_discovered_time = "AGENT_LAST_DISCOVERED_TIME"
    avd_enabled = "AVD_ENABLED"
    cloud_provider = "CLOUD_PROVIDER"
    coverage_type = "COVERAGE_TYPE"
    cvss_attack_complexity = "CVSS_ATTACK_COMPLEXITY"
    cvss_attack_vector = "CVSS_ATTACK_VECTOR"
    cvss_authentication = "CVSS_AUTHENTICATION"
    cvss_availability = "CVSS_AVAILABILITY"
    cvss_confidentiality = "CVSS_CONFIDENTIALITY"
    cvss_exploitability_score = "CVSS_EXPLOITABILITY_SCORE"
    cvss_impact_score = "CVSS_IMPACT_SCORE"
    cvss_integrity = "CVSS_INTEGRITY"
    cvss_privileges_required = "CVSS_PRIVILEGES_REQUIRED"
    cvss_scope = "CVSS_SCOPE"
    cvss_score = "CVSS_SCORE"
    cvss_user_interaction = "CVSS_USER_INTERACTION"
    cvss_vector_string = "CVSS_VECTOR_STRING"
    cvss_version = "CVSS_VERSION"
    external_ip = "EXTERNAL_IP"
    fixable = "FIXABLE"
    fix_version = "FIX_VERSION"
    host_first_discovered_time = "HOST_FIRST_DISCOVERED_TIME"
    host_last_discovered_time = "HOST_LAST_DISCOVERED_TIME"
    host_last_eval_time = "HOST_LAST_EVAL_TIME"
    host_machine_id = "HOST_MACHINE_ID"
    host_mid = "HOST_MID"
    host_name = "HOST_NAME"
    host_risk_info = "HOST_RISK_INFO"
    host_risk_score = "HOST_RISK_SCORE"
    internal_ip = "INTERNAL_IP"
    internet_exposed = "INTERNET_EXPOSED"
    internet_exposed_last_updated = "INTERNET_EXPOSED_LAST_UPDATED"
    machine_image = "MACHINE_IMAGE"
    machine_status = "MACHINE_STATUS"
    machine_status_text = "MACHINE_STATUS_TEXT"
    machine_tags = "MACHINE_TAGS"
    observation_first_discovered_time = "OBSERVATION_FIRST_DISCOVERED_TIME"
    observation_fixed_time = "OBSERVATION_FIXED_TIME"
    observation_last_discovered_time = "OBSERVATION_LAST_DISCOVERED_TIME"
    observation_status = "OBSERVATION_STATUS"
    observation_status_category = "OBSERVATION_STATUS_CATEGORY"
    observation_status_category_text = "OBSERVATION_STATUS_CATEGORY_TEXT"
    observation_status_text = "OBSERVATION_STATUS_TEXT"
    observation_vulnerable_since_time = "OBSERVATION_VULNERABLE_SINCE_TIME"
    organization_id = "ORGANIZATION_ID"
    os_eol_date = "OS_EOL_DATE"
    os_name = "OS_NAME"
    os_namespace = "OS_NAMESPACE"
    os_out_of_date = "OS_OUT_OF_DATE"
    os_reboot_required = "OS_REBOOT_REQUIRED"
    os_type = "OS_TYPE"
    os_updates_disabled = "OS_UPDATES_DISABLED"
    os_version = "OS_VERSION"
    package_last_active_time = "PACKAGE_LAST_ACTIVE_TIME"
    package_name = "PACKAGE_NAME"
    package_namespace = "PACKAGE_NAMESPACE"
    package_path = "PACKAGE_PATH"
    package_status = "PACKAGE_STATUS"
    package_status_text = "PACKAGE_STATUS_TEXT"
    package_version = "PACKAGE_VERSION"
    public_facing = "PUBLIC_FACING"
    severity = "SEVERITY"
    severity_text = "SEVERITY_TEXT"
    vuln_description = "VULN_DESCRIPTION"
    vuln_id = "VULN_ID"
    vuln_link = "VULN_LINK"
    vuln_public_exploit_available = "VULN_PUBLIC_EXPLOIT_AVAILABLE"
    vuln_public_exploit_date = "VULN_PUBLIC_EXPLOIT_DATE"
    zone = "ZONE"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class UniqueVulnByImageReturnFields:
    active_container_count = "ACTIVE_CONTAINER_COUNT"
    cvss_attack_complexity = "CVSS_ATTACK_COMPLEXITY"
    cvss_attack_vector = "CVSS_ATTACK_VECTOR"
    cvss_authentication = "CVSS_AUTHENTICATION"
    cvss_availability = "CVSS_AVAILABILITY"
    cvss_confidentiality = "CVSS_CONFIDENTIALITY"
    cvss_exploitability_score = "CVSS_EXPLOITABILITY_SCORE"
    cvss_impact_score = "CVSS_IMPACT_SCORE"
    cvss_integrity = "CVSS_INTEGRITY"
    cvss_privileges_required = "CVSS_PRIVILEGES_REQUIRED"
    cvss_scope = "CVSS_SCOPE"
    cvss_score = "CVSS_SCORE"
    cvss_user_interaction = "CVSS_USER_INTERACTION"
    cvss_vector_string = "CVSS_VECTOR_STRING"
    cvss_version = "CVSS_VERSION"
    fixable = "FIXABLE"
    fix_version = "FIX_VERSION"
    has_active_containers = "HAS_ACTIVE_CONTAINERS"
    has_avd_enabled_containers = "HAS_AVD_ENABLED_CONTAINERS"
    image_created_time = "IMAGE_CREATED_TIME"
    image_digests = "IMAGE_DIGESTS"
    image_first_discovered_time = "IMAGE_FIRST_DISCOVERED_TIME"
    image_id = "IMAGE_ID"
    image_last_discovered_time = "IMAGE_LAST_DISCOVERED_TIME"
    image_last_scan_time = "IMAGE_LAST_SCAN_TIME"
    image_latest_scan_successful = "IMAGE_LATEST_SCAN_SUCCESSFUL"
    image_latest_successful_scan_time = "IMAGE_LATEST_SUCCESSFUL_SCAN_TIME"
    image_names = "IMAGE_NAMES"
    image_registries = "IMAGE_REGISTRIES"
    image_repositories = "IMAGE_REPOSITORIES"
    image_request_sources = "IMAGE_REQUEST_SOURCES"
    image_risk_info = "IMAGE_RISK_INFO"
    image_risk_score = "IMAGE_RISK_SCORE"
    image_risk_score_last_updated = "IMAGE_RISK_SCORE_LAST_UPDATED"
    image_scan_error_message = "IMAGE_SCAN_ERROR_MESSAGE"
    image_scan_status = "IMAGE_SCAN_STATUS"
    image_size = "IMAGE_SIZE"
    image_tags = "IMAGE_TAGS"
    image_type = "IMAGE_TYPE"
    internet_exposed = "INTERNET_EXPOSED"
    internet_exposed_last_updated = "INTERNET_EXPOSED_LAST_UPDATED"
    observation_first_discovered_time = "OBSERVATION_FIRST_DISCOVERED_TIME"
    observation_fixed_time = "OBSERVATION_FIXED_TIME"
    observation_last_discovered_time = "OBSERVATION_LAST_DISCOVERED_TIME"
    observation_status = "OBSERVATION_STATUS"
    observation_status_category = "OBSERVATION_STATUS_CATEGORY"
    observation_status_category_text = "OBSERVATION_STATUS_CATEGORY_TEXT"
    observation_status_text = "OBSERVATION_STATUS_TEXT"
    observation_vulnerable_since_time = "OBSERVATION_VULNERABLE_SINCE_TIME"
    os = "OS"
    package_last_active_time = "PACKAGE_LAST_ACTIVE_TIME"
    package_name = "PACKAGE_NAME"
    package_namespace = "PACKAGE_NAMESPACE"
    package_path = "PACKAGE_PATH"
    package_status = "PACKAGE_STATUS"
    package_status_text = "PACKAGE_STATUS_TEXT"
    package_version = "PACKAGE_VERSION"
    severity = "SEVERITY"
    severity_text = "SEVERITY_TEXT"
    vuln_description = "VULN_DESCRIPTION"
    vuln_id = "VULN_ID"
    vuln_link = "VULN_LINK"
    vuln_public_exploit_available = "VULN_PUBLIC_EXPLOIT_AVAILABLE"
    vuln_public_exploit_date = "VULN_PUBLIC_EXPLOIT_DATE"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class VulnerabilitiesReturnFields:
    cvss_attack_complexity = "CVSS_ATTACK_COMPLEXITY"
    cvss_attack_vector = "CVSS_ATTACK_VECTOR"
    cvss_authentication = "CVSS_AUTHENTICATION"
    cvss_availability = "CVSS_AVAILABILITY"
    cvss_confidentiality = "CVSS_CONFIDENTIALITY"
    cvss_exploitability_score = "CVSS_EXPLOITABILITY_SCORE"
    cvss_impact_score = "CVSS_IMPACT_SCORE"
    cvss_integrity = "CVSS_INTEGRITY"
    cvss_privileges_required = "CVSS_PRIVILEGES_REQUIRED"
    cvss_scope = "CVSS_SCOPE"
    cvss_score = "CVSS_SCORE"
    cvss_user_interaction = "CVSS_USER_INTERACTION"
    cvss_vector_string = "CVSS_VECTOR_STRING"
    cvss_version = "CVSS_VERSION"
    description = "DESCRIPTION"
    entity_count_avd_enabled = "ENTITY_COUNT_AVD_ENABLED"
    entity_count_internet_exposed = "ENTITY_COUNT_INTERNET_EXPOSED"
    entity_count_total_vulnerable = "ENTITY_COUNT_TOTAL_VULNERABLE"
    first_discovered_time = "FIRST_DISCOVERED_TIME"
    first_vulnerable_logged_time = "FIRST_VULNERABLE_LOGGED_TIME"
    fixable = "FIXABLE"
    host_count_avd_enabled = "HOST_COUNT_AVD_ENABLED"
    host_count_exception = "HOST_COUNT_EXCEPTION"
    host_count_internet_exposed = "HOST_COUNT_INTERNET_EXPOSED"
    host_count_not_vulnerable = "HOST_COUNT_NOT_VULNERABLE"
    host_count_vulnerable = "HOST_COUNT_VULNERABLE"
    image_count_avd_enabled = "IMAGE_COUNT_AVD_ENABLED"
    image_count_exception = "IMAGE_COUNT_EXCEPTION"
    image_count_internet_exposed = "IMAGE_COUNT_INTERNET_EXPOSED"
    image_count_not_vulnerable = "IMAGE_COUNT_NOT_VULNERABLE"
    image_count_vulnerable = "IMAGE_COUNT_VULNERABLE"
    last_discovered_time = "LAST_DISCOVERED_TIME"
    last_vulnerable_logged_time = "LAST_VULNERABLE_LOGGED_TIME"
    link = "LINK"
    package_names_exception = "PACKAGE_NAMES_EXCEPTION"
    package_names_not_vulnerable = "PACKAGE_NAMES_NOT_VULNERABLE"
    package_names_vulnerable = "PACKAGE_NAMES_VULNERABLE"
    public_exploit_available = "PUBLIC_EXPLOIT_AVAILABLE"
    public_exploit_date = "PUBLIC_EXPLOIT_DATE"
    risk_info = "RISK_INFO"
    risk_score = "RISK_SCORE"
    risk_score_last_updated = "RISK_SCORE_LAST_UPDATED"
    severity = "SEVERITY"
    severity_text = "SEVERITY_TEXT"
    vuln_id = "VULN_ID"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class ImageReturnFields:
    active = "ACTIVE"
    active_container_account_aliases = "ACTIVE_CONTAINER_ACCOUNT_ALIASES"
    active_container_account_ids = "ACTIVE_CONTAINER_ACCOUNT_IDS"
    active_container_avd_enabled = "ACTIVE_CONTAINER_AVD_ENABLED"
    active_container_count = "ACTIVE_CONTAINER_COUNT"
    active_container_k8s_clusters = "ACTIVE_CONTAINER_K8S_CLUSTERS"
    active_container_machine_ids = "ACTIVE_CONTAINER_MACHINE_IDS"
    active_container_organization_ids = "ACTIVE_CONTAINER_ORGANIZATION_IDS"
    active_container_pod_names = "ACTIVE_CONTAINER_POD_NAMES"
    active_container_pod_namespaces = "ACTIVE_CONTAINER_POD_NAMESPACES"
    active_container_privileged = "ACTIVE_CONTAINER_PRIVILEGED"
    container_count = "CONTAINER_COUNT"
    digests = "DIGESTS"
    entity_status_category = "ENTITY_STATUS_CATEGORY"
    entity_status_category_text = "ENTITY_STATUS_CATEGORY_TEXT"
    first_active_time = "FIRST_ACTIVE_TIME"
    first_discovered_time = "FIRST_DISCOVERED_TIME"
    has_active_containers = "HAS_ACTIVE_CONTAINERS"
    has_avd_enabled_containers = "HAS_AVD_ENABLED_CONTAINERS"
    image_created_time = "IMAGE_CREATED_TIME"
    image_id = "IMAGE_ID"
    image_names = "IMAGE_NAMES"
    image_registries = "IMAGE_REGISTRIES"
    image_repositories = "IMAGE_REPOSITORIES"
    image_size = "IMAGE_SIZE"
    image_tags = "IMAGE_TAGS"
    image_type = "IMAGE_TYPE"
    internet_exposed = "INTERNET_EXPOSED"
    internet_exposed_last_updated = "INTERNET_EXPOSED_LAST_UPDATED"
    last_active_time = "LAST_ACTIVE_TIME"
    last_discovered_time = "LAST_DISCOVERED_TIME"
    last_scan_time = "LAST_SCAN_TIME"
    latest_scan_successful = "LATEST_SCAN_SUCCESSFUL"
    latest_successful_scan_time = "LATEST_SUCCESSFUL_SCAN_TIME"
    os = "OS"
    package_count_exception = "PACKAGE_COUNT_EXCEPTION"
    package_count_not_vulnerable = "PACKAGE_COUNT_NOT_VULNERABLE"
    package_count_vulnerable = "PACKAGE_COUNT_VULNERABLE"
    request_sources = "REQUEST_SOURCES"
    risk_info = "RISK_INFO"
    risk_score = "RISK_SCORE"
    risk_score_last_updated = "RISK_SCORE_LAST_UPDATED"
    scan_error_message = "SCAN_ERROR_MESSAGE"
    scan_status = "SCAN_STATUS"
    status = "STATUS"
    status_text = "STATUS_TEXT"
    vuln_count_critical = "VULN_COUNT_CRITICAL"
    vuln_count_critical_fixable = "VULN_COUNT_CRITICAL_FIXABLE"
    vuln_count_high = "VULN_COUNT_HIGH"
    vuln_count_high_fixable = "VULN_COUNT_HIGH_FIXABLE"
    vuln_count_info = "VULN_COUNT_INFO"
    vuln_count_info_fixable = "VULN_COUNT_INFO_FIXABLE"
    vuln_count_low = "VULN_COUNT_LOW"
    vuln_count_low_fixable = "VULN_COUNT_LOW_FIXABLE"
    vuln_count_medium = "VULN_COUNT_MEDIUM"
    vuln_count_medium_fixable = "VULN_COUNT_MEDIUM_FIXABLE"
    vuln_count_total = "VULN_COUNT_TOTAL"
    vuln_count_total_fixable = "VULN_COUNT_TOTAL_FIXABLE"

    @classmethod
    def generate_return_payload(cls) -> list:
        """Return a list of return fields used to query new Vuln dashboard"""
        returns = []
        for key, value in cls.__dict__.items():
            if isinstance(value, str) and not key.startswith("__"):
                returns.append({
                    "field": value
                })
        return returns


class ResourceTypes:
    PREFIX = "LACEWORK_RESOURCE_GROUP_"
    ALL_OCI = PREFIX + "ALL_OCI"
    ALL_AWS = PREFIX + "ALL_AWS"
    ALL_AZURE = PREFIX + "ALL_AZURE"
    ALL_CONTAINER = PREFIX + "ALL_CONTAINER"
    ALL_GCP = PREFIX + "ALL_GCP"
    ALL_KUBERNETES = PREFIX + "ALL_KUBERNETES"
    ALL_MACHINE = PREFIX + "ALL_MACHINE"

    @classmethod
    def all_resource_types(cls):
        """Return a list of all resource types"""
        return [value for key, value in cls.__dict__.items() if key.isupper() and key != "PREFIX"]


class QueryEntity(Enum):
    HOSTS = "hosts"
    CVES = "cves"
    CONTAINER_IMAGE = "container_images"
    PACKAGES = "packages"
    UNIQUE_VULN_BY_HOST = "unique_vuln_by_host"
    UNIQUE_VULN_BY_IMAGE = "unique_vuln_by_image"


@dataclass
class Filter:
    type: str
    key: str
    value: Union[str, int, float, List[Union[str, int, float]], Dict[str, str]]
    operator: ComparisonOperator


@dataclass
class NewVulnDataclass:
    type: QueryEntity  # Show, for example, show Hosts
    filters: List[Filter] = field(default_factory=list)

    def add_filter(self, key: str, type: str, value: Union[str, int, float, List[Union[str, int, float]]], operator: ComparisonOperator):
        """Add Filter object to the Vuln Dataclass"""
        new_filter = Filter(key=key, type=type, value=value, operator=operator)
        self.filters.append(new_filter)
        return new_filter
