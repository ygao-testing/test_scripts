from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Union


class ComparisonOperator(Enum):
    IS_IN = "in"
    IS_EQUAL_TO = "eq"
    IS_ANY_OF = "anyOf"
    IS_NOT_EQUAL_TO = "ne"
    IS_LESS_THAN = "lt"
    IS_LESS_THAN_OR_EQUAL_TO = "lte"
    IS_GREATER_THAN = "gt"
    IS_GREATER_THAN_OR_EQUAL_TO = "gte"
    STARTS_WITH = "startsWith"
    ENDS_WITH = "endsWith"


class ResourceGroups(Enum):
    ALL_AWS_RESOURCES = "LACEWORK_RESOURCE_GROUP_ALL_AWS"
    ALL_AZURE_RESOURCES = "LACEWORK_RESOURCE_GROUP_ALL_AZURE"
    ALL_CONTAINER_RESOURCES = "LACEWORK_RESOURCE_GROUP_ALL_CONTAINER"
    ALL_GCP_RESOURCES = "LACEWORK_RESOURCE_GROUP_ALL_GCP"
    ALL_KUBERNETES_RESOURCES = "LACEWORK_RESOURCE_GROUP_ALL_KUBERNETES"
    ALL_MACHINES = "LACEWORK_RESOURCE_GROUP_ALL_MACHINE"
    ALL_OCI_RESOURCES = "LACEWORK_RESOURCE_GROUP_ALL_OCI"

    @classmethod
    def all_resource_groups(cls):
        """Return a list of all resource groups"""
        return [member for member in cls]


class IdentityResourceTypes(Enum):
    AWS_IAM_ROLE = "AWS_IAM_ROLE"
    AWS_IAM_USER = "AWS_IAM_USER"
    AZURE_AUTHORIZATION_ROLE_DEFINITION = "AZURE_AUTHORIZATION_ROLEDEFINITION"
    GCP_IAM_ROLE = "GCP_IAM_ROLE"
    GCP_IAM_SERVICE_ACCOUNT = "GCP_IAM_SERVICEACCOUNT"

    @classmethod
    def all_resource_types(cls):
        """Return a list of all identity related resource types"""
        return [member for member in cls]


class IdentityResourceTypesV2(Enum):
    AWS_IAM_ROLE = "AWS_IAM_ROLE"
    AWS_IAM_USER = "AWS_IAM_USER"
    AWS_IAM_GROUP = "AWS_IAM_GROUP"
    AWS_IDENTITYSTORE_USER = "AWS_IDENTITYSTORE_USER"
    AWS_IDENTITYSTORE_GROUP = "AWS_IDENTITYSTORE_GROUP"
    AZURE_ROLE_DEFINITION = "AZURE_ROLE_DEFINITION"
    GCP_IAM_ROLE = "GCP_IAM_ROLE"
    GCP_IAM_SERVICE_ACCOUNT = "GCP_IAM_SERVICE_ACCOUNT"

    @classmethod
    def all_resource_types(cls):
        """Return a list of all identity related resource types"""
        return [member for member in cls]


class StorageResourceTypes(Enum):
    AWS_RDS_CLUSTER = "AWS_RDS_CLUSTER"
    AWS_RDS_DB = "AWS_RDS_DB"
    AWS_S3_BUCKET = "AWS_S3_BUCKET"
    AWS_DYNAMODB_TABLE = "AWS_DYNAMODB_TABLE"
    AWS_KMS_KEY = "AWS_KMS_KEY"
    AZURE_SERVERS_DATABASES = "AZURE_SERVERS_DATABASES"
    AZURE_DATABASES = "AZURE_DATABASES"
    AZURE_STORAGE_ACCOUNTS = "AZURE_STORAGE_ACCOUNTS"
    AZURE_KEYVAULT_VAULTS = "AZURE_KEYVAULT_VAULTS"
    GCP_STORAGE_BUCKET = "GCP_STORAGE_BUCKET"
    GCP_BIGQUERY_DATASET = "GCP_BIGQUERY_DATASET"
    GCP_SQLADMIN_INSTANCE = "GCP_SQLADMIN_INSTANCE"
    GCP_FIRESTORE_DATABASE = "GCP_FIRESTORE_DATABASE"
    GCP_CLOUDKMS_CRYPTOKEY = "GCP_CLOUDKMS_CRYPTOKEY"

    @classmethod
    def all_resource_types(cls):
        """Return a list of all storage related resource types"""
        return [member for member in cls]


class StorageResourceTypesV2(Enum):
    AWS_RDS_CLUSTER = "AWS_RDS_CLUSTER"
    AWS_RDS_DB = "AWS_RDS_DB"
    AWS_S_3_BUCKET = "AWS_S_3_BUCKET"
    AWS_DYNAMODB_TABLE = "AWS_DYNAMODB_TABLE"
    AWS_KMS_KEY = "AWS_KMS_KEY"
    AZURE_SQL_DATABASE = "AZURE_SQL_DATABASE"
    AZURE_DATABASE = "AZURE_DATABASE"
    AZURE_STORAGE_ACCOUNT = "AZURE_STORAGE_ACCOUNT"
    AZURE_KEYVAULT_VAULT = "AZURE_KEYVAULT_VAULT"
    GCP_STORAGE_BUCKET = "GCP_STORAGE_BUCKET"
    GCP_BIGQUERY_DATASET = "GCP_BIGQUERY_DATASET"
    GCP_SQLADMIN_INSTANCE = "GCP_SQLADMIN_INSTANCE"
    GCP_FIRESTORE_DATABASE = "GCP_FIRESTORE_DATABASE"
    GCP_CLOUDKMS_CRYPTOKEY = "GCP_CLOUDKMS_CRYPTOKEY"

    @classmethod
    def all_resource_types(cls):
        """Return a list of all storage related resource types"""
        return [member for member in cls]


class AgentlessResourceInventoryFilter:
    PREFIX = "Agentless_RESOURCE_INVENTORY_Filter."
    resource_type = PREFIX + "RESOURCE_TYPE"
    resource_id = PREFIX + "RESOURCE_ID"
    resource_name = PREFIX + "RESOURCE_NAME"
    provider = PREFIX + "PROVIDER"
    region = PREFIX + "REGION"
    os = PREFIX + "OS"
    account = PREFIX + "ACCOUNT"
    account_alias = PREFIX + "ACCOUNT_ALIAS"
    org_id = PREFIX + "ORG_ID"
    last_scan_status = PREFIX + "LAST_SCAN_STATUS"
    last_scan_details = PREFIX + "LAST_SCAN_DETAILS"
    failure_reason = PREFIX + "FAILURE_REASON"


class AgentlessCloudAccountInventoryFilter:
    PREFIX = "Agentless_CLOUD_ACCOUNTS_INVENTORY_Filter."
    provider = PREFIX + "PROVIDER"
    region = PREFIX + "REGION"
    account = PREFIX + "ACCOUNT"
    account_alias = PREFIX + "ACCOUNT_ALIAS"
    org_id = PREFIX + "ORG_ID"
    failure_reason = PREFIX + "FAILURE_REASON"
    agentless_configuration = PREFIX + "AWLS_INTEGRATED"


class ContainerVulnerabilityFilter:
    PREFIX = "Vuln_Filters."
    fixable = PREFIX + "FIXABLE_MV"
    cve_status = PREFIX + "CVE_STATUS"
    cve_severity = PREFIX + "CVE_SEVERITY_MV"
    vuln_id = PREFIX + "VULN_ID_MV"
    package_name = PREFIX + "CVE_PACKAGE_NAME_MV"
    package_version = PREFIX + "CVE_PACKAGE_VERSION_MV"
    container_privileged = PREFIX + "PRIVILEGED"
    policy_assessment = PREFIX + "POLICY_STATUS_I"
    scanner_type = PREFIX + "REQUEST_SOURCE"
    internet_exposed = PREFIX + "INTERNET_EXPOSURE"
    host_name = PREFIX + "HOSTNAME"
    image_id = PREFIX + "IMAGE_ID"
    image_registry = PREFIX + "IMAGE_REPO"
    image_repository = PREFIX + "REQUEST_SOURCE"
    image_tag = PREFIX + "IMAGE_TAGS"
    user = PREFIX + "USER"
    pod_namespace = PREFIX + "POD_NAMESPACES"
    k8s_cluster = PREFIX + "K8S_CLUSTERS"
    machine_tags = PREFIX + "TAGS"
    exploit_available = PREFIX + "IMAGEID_CVSS_EXPLOIT_AVAILABLE"
    cvss_score = PREFIX + "IMAGEID_CVSS_SCORE"
    cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_ATTACK_VECTOR"
    cvss_vectors_attack_complexity = cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_ATTACK_COMPLEXITY"
    cvss_vectors_privileges_required = cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_PRIVILEGES_REQUIRED"
    cvss_vectors_user_interation = cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_USER_INTERACTION"
    cvss_vectors_scope = cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_SCOPE"
    cvss_vectors_availability_impact = cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_AVAILABILITY"
    cvss_vectors_confidentiality_integrity_impact = cvss_vectores = PREFIX + "IMAGEID_CVSS_ATTRIBUTE_CONFIDENTIALITY_INTEGRITY"


class AgentFilter:
    PREFIX = "AGENT_FLEET_Filters."
    AGENT_VERSION = PREFIX + "AGENT_VERSION"
    OS = PREFIX + "OS"
    HOSTNAME = PREFIX + "HOSTNAME"
    IP_ADDRESS = PREFIX + "IP_ADDRESS"
    STATUS = PREFIX + "STATUS"
    AUTOUPGRADE = PREFIX + "AUTOUPGRADE"
    TOKEN = PREFIX + "TOKEN"
    INSTANCE_ID = PREFIX + "INSTANCE_ID"

    @classmethod
    def all_filters(cls):
        """Return a list of all resource types"""
        return [key for key, value in cls.__dict__.items() if key.isupper() and key != "PREFIX"]

    @classmethod
    def all_filters_in_api_test(cls):
        """Return a list of all resource types"""
        return [key for key, value in cls.__dict__.items() if key.isupper() and key not in ["PREFIX", "STATUS", "AUTOUPGRADE", "AGENT_VERSION"]]


class LaceworkResourceGroupFilter:
    PREFIX = "LACEWORK_RESOURCE_GROUP_"
    AWS = PREFIX + "ALL_AWS"
    AZURE = PREFIX + "ALL_AZURE"
    CONTAINER = PREFIX + "ALL_CONTAINER"
    GCP = PREFIX + "ALL_GCP"
    KUBERNETES = PREFIX + "ALL_KUBERNETES"
    MACHINE = PREFIX + "ALL_MACHINE"
    OCI = PREFIX + "ALL_OCI"

    @classmethod
    def all_resource_types(cls):
        """Return a list of all resource types"""
        return [value for key, value in cls.__dict__.items() if key.isupper() and key != "PREFIX"]


@dataclass
class SubFilter:
    key: str
    operator: Optional[ComparisonOperator]
    value: Union[str, int, float]


@dataclass
class Filter:
    key: str
    value: Optional[Union[str, int, float]] = None
    operator: Optional[ComparisonOperator] = None
    subfilters: List[SubFilter] = field(default_factory=list)

    def add_subfilter(self, key: str, operator: ComparisonOperator, value: Union[str, int, float]):
        """Add subfilter object to Filter"""
        self.subfilters.append(SubFilter(key=key, operator=operator, value=value))


@dataclass
class Connector:
    # In GraphQL, it has `that can be access by`, which means a connection between 2 different objects
    type: str


@dataclass
class GraphQLFilter:
    type: str
    filters: List[Filter] = field(default_factory=list)
    connection: Optional[Connector] = None

    def add_filter(self, key: str, value: Optional[Union[str, int, float]] = None, operator: Optional[ComparisonOperator] = None):
        """Add Filter object to the GraphQLFilter"""
        new_filter = Filter(key=key, value=value, operator=operator)
        self.filters.append(new_filter)
        return new_filter

    def add_connector(self, type: str):
        """Add Connector object to the GraphQLFilter"""
        connector = Connector(type=type)
        self.connection = connector
        return connector


class AlertMetadataFilter:
    PREFIX = "AlertMetadataFilters."
    SEVERITY = PREFIX + "SEVERITY"
    SOURCE = PREFIX + "SOURCE"
    STATUS = PREFIX + "STATUS"
    SUB_CATEGORY = PREFIX + "SUB_CATEGORY"


class CloudTrailFilters:
    PREFIX = "CloudTrailFilters."
    AWS_API = PREFIX + "AWS_API"
    AWS_ACCOUNT_CALLER = PREFIX + "AWS_ACCOUNT_CALLER"
    AWS_EVENT_ID = PREFIX + "AWS_EVENT_ID"
    AWS_REGION = PREFIX + "AWS_REGION"
    AWS_SERVICE = PREFIX + "AWS_SERVICE"
    AWS_SOURCE = PREFIX + "AWS_SOURCE"
    AWS_USERNAME = PREFIX + "AWS_USERNAME"
    PRINCIPAL_ID = PREFIX + "PRINCIPAL_ID"
    AWS_ACCOUNT_CALLEE = PREFIX + "AWS_ACCOUNT_CALLEE"

    @classmethod
    def all_cloudtrail_filters(cls):
        """Return a list of all resource types"""
        return [value for key, value in cls.__dict__.items() if key.isupper() and key != "PREFIX" and key != "AWS_ACCOUNT_CALLEE"]


class AuditLogFilters:
    PREFIX = "GCPAuditLogFilters."
    PROJECT_ID = PREFIX + "PROJECT_ID"
    GCP_EVENT_ID = PREFIX + "GCP_EVENT_ID"
    METHOD_NAME = PREFIX + "METHOD_NAME"
    PROJECT_ID = PREFIX + "PROJECT_ID"
    PROJECT_NAME = PREFIX + "PROJECT_NAME"
    REGION = PREFIX + "REGION"
    SERVICE_NAME = PREFIX + "SERVICE_NAME"
    PRINCIPAL_EMAIL = PREFIX + "PRINCIPAL_EMAIL"
    CALLER_IP = PREFIX + "CALLER_IP"
    # Missing one navigationKey, name it ORG for now
    ORG = PREFIX + "ORG"

    @classmethod
    def all_cloudtrail_filters(cls):
        """Return a list of all resource types"""
        return [value for key, value in cls.__dict__.items() if key.isupper() and key != "PREFIX" and key != "ORG"]


class AcitivityLogFilters:
    PREFIX = "AzureActivityLogFilters."
    CALLER_IP = PREFIX + "CALLER_IP"
    EVENT_CATEGORY = PREFIX + "EVENT_CATEGORY"
    OPERATION_NAME = PREFIX + "OPERATION_NAME"
    PRINCIPAL_ID = PREFIX + "PRINCIPAL_ID"
    PROVIDER_NAME = PREFIX + "PROVIDER_NAME"
    SUBSCRIPTION_NAME = PREFIX + "SUBSCRIPTION_NAME"
    TENANT_NAME = PREFIX + "TENANT_NAME"
    USER_NAME = PREFIX + "USER_NAME"

    @classmethod
    def all_cloudtrail_filters(cls):
        """Return a list of all resource types"""
        return [value for key, value in cls.__dict__.items() if key.isupper() and key != "PREFIX" and key != "ORG"]
