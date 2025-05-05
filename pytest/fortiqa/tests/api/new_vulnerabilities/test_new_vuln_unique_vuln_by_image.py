import logging
import pytest

from fortiqa.libs.lw.apiv1.api_client.new_vuln.payloads import NewVulnDataclass, QueryEntity, ComparisonOperator
from fortiqa.tests.api.new_vulnerabilities.conftest import generate_new_vuln_payload_and_query

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


@pytest.mark.parametrize("vuln_id", [
    "CVE-2001-1454",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.STARTS_WITH

])
def test_show_unique_vulnerabilities_by_image_vulnerability_id(api_v1_client, vuln_id, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability->Vuln Id

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability->Vuln Id
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_id: A list of vuln_id
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnFilter",
                            key="VULN_ID",
                            value=vuln_id,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("vuln_severity", [
    ["1", "2", "3", "4", "5"]
])
def test_show_unique_vulnerabilities_by_image_vulnerability_severity(api_v1_client, vuln_severity):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability->Severity

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability->Severity
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_severity: A list of vuln_severity
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnFilter",
                            key="SEVERITY",
                            value=vuln_severity,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("vuln_risk_score", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO

])
def test_show_unique_vulnerabilities_by_image_vulnerability_risk_score(api_v1_client, vuln_risk_score, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability->Risk Score

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability->Risk Score
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_risk_score: Risk Score
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnFilter",
                            key="VULN_RISK_SCORE",
                            value=vuln_risk_score,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("vuln_description", [
    "abc",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.STARTS_WITH

])
def test_show_unique_vulnerabilities_by_image_vulnerability_description(api_v1_client, vuln_description, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability->Description

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability->Description
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_description: Description
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnFilter",
                            key="DESCRIPTION",
                            value=vuln_description,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("vuln_exploit", [
    "true",
    "false"
])
def test_show_unique_vulnerabilities_by_image_vulnerability_exploit(api_v1_client, vuln_exploit):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability->Exploit Available

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability->Exploit Available
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vuln_exploit: Exploit Available option
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnFilter",
                            key="PUBLIC_EXPLOIT_AVAILABLE",
                            value=vuln_exploit,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("package_name", [
    "PyYAML",
    "apache-log4j1.2",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_unique_vulnerabilities_by_image_package_name(api_v1_client, package_name, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Package->Package/Application name

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Package->Package/Application name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_name: Package/Application Name
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_NAME",
                            value=package_name,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("package_name_space", [
    "alpine:v3.21",
    "amzn:2016.09",
    "python",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_unique_vulnerabilities_by_image_package_name_space(api_v1_client, package_name_space, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Package->Package Namespace

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Package->Package Namespace
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_name_space: Package Namespace
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_NAMESPACE",
                            value=package_name_space,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("package_path", [
    "opt",
    "opt/java",
    "123"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.STARTS_WITH,
    ComparisonOperator.IS_NOT_EQUAL_TO,
    ComparisonOperator.CONTAINS

])
def test_show_unique_vulnerabilities_by_image_package_path(api_v1_client, package_path, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Package->Package Path

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Package->Package Path
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_path: Package Path
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnObservationFilters",
                            key="PACKAGE_PATH",
                            value=package_path,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("package_risk_score", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_unique_vulnerabilities_by_image_package_risk_score(api_v1_client, package_risk_score, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Package->Risk Score

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Package->Risk Score
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_risk_score: Package Risk Score
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_RISK_SCORE",
                            value=package_risk_score,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("package_status", [
   ["1", "0"],
   ["-2", "-1"],
   ["-3", "2"]
])
def test_show_unique_vulnerabilities_by_image_package_status(api_v1_client, package_status):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Package->Package Status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Package->Package Status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_status: Package Status
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnObservationFilters",
                            key="PACKAGE_STATUS",
                            value=package_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("package_version", [
    "0.0.12+nmu1",
    "123",
    "0.0.22"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.STARTS_WITH,
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.CONTAINS

])
def test_show_unique_vulnerabilities_by_image_package_version(api_v1_client, package_version, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Package->Package/Application Version

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Package->Package/Application Version
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        package_version: Package/Application Version
        operator: Operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="PackageFilter",
                            key="PACKAGE_VERSION",
                            value=package_version,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("vulnerability_status_category", [
   ["1", "0"],
   ["-1", "-1"],
   ["-2", "2"]
])
def test_show_unique_vulnerabilities_by_image_vulnerability_status_category(api_v1_client, vulnerability_status_category):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability Observation->Vulnerability status category

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability Observation->Vulnerability status category
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vulnerability_status_category: Vulnerability Status Category
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnObservationFilters",
                            key="STATUS_CATEGORY",
                            value=vulnerability_status_category,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("vulnerability_status", [
   ["4", "3", "2", "1", "-1"],
   ["-2", "0"]
])
def test_show_unique_vulnerabilities_by_image_vulnerability_status(api_v1_client, vulnerability_status):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability Observation->status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability Observation->status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        vulnerability_status: Vulnerability Status
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnObservationFilters",
                            key="STATUS",
                            value=vulnerability_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("entity_vulnerability_status", [
   ["1", "-1", "0"],
   ["-2", "2"]
])
@pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/VULN-1068")
def test_show_unique_vulnerabilities_by_image_entity_vulnerability_status(api_v1_client, entity_vulnerability_status):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability Observation->Entity Vulnerability Status

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability Observation->status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        entity_vulnerability_status: Entity Status Category
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnObservationFilters",
                            key="ENTITY_STATUS_CATEGORY",
                            value=entity_vulnerability_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("entity_type", [
   ["PACKAGEMachine", "Image"],
   ["abc", "123"]
])
def test_show_unique_vulnerabilities_by_image_entity_type(api_v1_client, entity_type):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Vulnerability Observation->Entity type

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Vulnerability Observation->Entity type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        entity_type: Entity Type
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="VulnObservationFilters",
                            key="ENTITY_TYPE",
                            value=entity_type,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_name", [
    "471112895216.dkr.ecr.us-east-1.amazonaws.com/",
    "ubuntu"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.CONTAINS

])
def test_show_unique_vulnerabilities_by_image_image_name(api_v1_client, image_name, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image name

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image name
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_name: Image name
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_NAMES",
                            value=image_name,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_id", [
    "12",
    "ubuntu"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_unique_vulnerabilities_by_image_image_id(api_v1_client, image_id, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image Id

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image Id
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_id: Image Id
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_ID",
                            value=image_id,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_digest", [
    "12",
    "ubuntu"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO
])
def test_show_unique_vulnerabilities_by_image_image_digest(api_v1_client, image_digest, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image Digest

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image Digest
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_digest: Image Digest
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="DIGESTS",
                            value=image_digest,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("registry", [
    "amazonlinux",
    "dkr.ecr.us-east-1.amazonaws.com"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.CONTAINS
])
def test_show_unique_vulnerabilities_by_image_image_registry(api_v1_client, registry, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Registry

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Registry
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        registry: Registry
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_REGISTRIES",
                            value=registry,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("repository", [
    "amazonlinux",
    "ecr-test"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.CONTAINS
])
def test_show_unique_vulnerabilities_by_image_image_repository(api_v1_client, repository, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Repository

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Repository
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        repository: Repository
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_REPOSITORIES",
                            value=repository,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("active", [
    "true",
    "false"
])
def test_show_unique_vulnerabilities_by_image_image_active(api_v1_client, active):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Active

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Active
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        active: Image active option
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="HAS_ACTIVE_CONTAINERS",
                            value=active,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("avd_enabled", [
    "true",
    "false"
])
def test_show_unique_vulnerabilities_by_image_image_avd_enabled(api_v1_client, avd_enabled):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->AVD Enabled

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->AVD Enabled
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        avd_enabled: Image AVD Enabled option
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="HAS_AVD_ENABLED_CONTAINERS",
                            value=avd_enabled,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("internet_exposed", [
    "true",
    "false"
])
def test_show_unique_vulnerabilities_by_image_image_internet_exposed(api_v1_client, internet_exposed):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Internet exposed
    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Internet exposed
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        internet_exposed: Image Internet exposed option
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="INTERNET_EXPOSED",
                            value=internet_exposed,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("last_scan_successful", [
    "true",
    "false"
])
def test_show_unique_vulnerabilities_by_image_image_last_scan_successful(api_v1_client, last_scan_successful):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Last scan successful
    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Last scan successful
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        last_scan_successful: Last scan successful option
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="LATEST_SCAN_SUCCESSFUL",
                            value=last_scan_successful,
                            operator=ComparisonOperator.IS_EQUAL_TO)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_scan_status", [
    ["Error", "Partial", "Success", "Unscanned"]
])
def test_show_unique_vulnerabilities_by_image_image_scan_status(api_v1_client, image_scan_status):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image scan status
    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image scan status
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_scan_status: Image scan status
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="SCAN_STATUS",
                            value=image_scan_status,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_type", [
    "Docker",
    "Do"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.CONTAINS
])
def test_show_unique_vulnerabilities_by_image_image_type(api_v1_client, image_type, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image type

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_type: Image type
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_TYPE",
                            value=image_type,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_os", [
    "Linux",
    "inux"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.IS_NOT_ANY_OF,
    ComparisonOperator.CONTAINS
])
def test_show_unique_vulnerabilities_by_image_image_os(api_v1_client, image_os, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->OS

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->OS
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_os: Image OS
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="OS",
                            value=image_os,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_scanner_type", [
    ["agentless_scanner", "platform_scanner", "inline_scanner", "proxy_scanner"]
])
def test_show_unique_vulnerabilities_by_image_image_scanner_type(api_v1_client, image_scanner_type):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image scanner type
    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image scanner type
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_scanner_type: Image scanner types
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="REQUEST_SOURCES",
                            value=image_scanner_type,
                            operator=ComparisonOperator.IS_IN)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_risk_score", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO

])
def test_show_unique_vulnerabilities_by_image_image_risk_score(api_v1_client, image_risk_score, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Risk Score

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Risk Score
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_risk_score: Image Risk Score
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_RISK_SCORE",
                            value=image_risk_score,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_size_in_bytes", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO

])
def test_show_unique_vulnerabilities_by_image_image_size(api_v1_client, image_size_in_bytes, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image size

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image size
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_size_in_bytes: Image Size in Bytes
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_SIZE",
                            value=image_size_in_bytes,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("active_containers", [
    "10",
    "-1"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_EQUAL_TO,
    ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
    ComparisonOperator.IS_NOT_EQUAL_TO

])
def test_show_unique_vulnerabilities_by_image_image_active_containers(api_v1_client, active_containers, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Active Containers

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Active Containers
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        active_containers: Number of container last seen in the past 24 hours
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="ACTIVE_CONTAINER_COUNT",
                            value=active_containers,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_tag", [
    "ecr-test",
    "ubuntu",
    "abc"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.CONTAINS,
    ComparisonOperator.STARTS_WITH,
    pytest.param(ComparisonOperator.IS_NOT_EQUAL_TO, marks=pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/VULN-1075"))
])
def test_show_unique_vulnerabilities_by_image_image_tag(api_v1_client, image_tag, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Image tag

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Image tag
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_tag: Image tag
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="IMAGE_TAGS",
                            value=image_tag,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")


@pytest.mark.parametrize("image_account_id", [
    "cnapp",
    "47112895216",
    "abc"
])
@pytest.mark.parametrize("operator", [
    ComparisonOperator.IS_ANY_OF,
    ComparisonOperator.STARTS_WITH,
    ComparisonOperator.IS_NOT_ANY_OF

])
def test_show_unique_vulnerabilities_by_image_image_account_id(api_v1_client, image_account_id, operator):
    """
    Verify that New Vulnerability API returns status code 200 from Unique Vulnerabilities by container image->Container Image->Account Id

    Given: API V1 Client
    When: Call New Vulnerability API, using filter Unique Vulnerabilities by container image->Container Image->Account Id
    Then: Expect status code returned is 200, and no Error message returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        image_account_id: Cloud Account id
        operator: Comparison operator
    """
    query_object = NewVulnDataclass(type=QueryEntity.UNIQUE_VULN_BY_IMAGE)
    query_object.add_filter(type="ImageFilter",
                            key="ACCOUNT_ID",
                            value=image_account_id,
                            operator=operator)
    generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                        query_object=query_object,
                                        query_type="unique_vuln_by_image")
