import logging
import pytest
import json

from fortiqa.libs.lw.apiv1.helpers.cloud_logs.gcp_auditlog_helper import AuditLogHelper

logger = logging.getLogger(__name__)


def test_audit_log_events(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> Events graph

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->Events graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog Event graph")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_event_data_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside Event graph, but found None"


def test_audit_log_unique_users(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> Usernames graph

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->Unique user graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog Unique Usernames graph")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_unique_user_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside Unique Usernames graph, but found None"


def test_audit_log_unique_methods(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> Unique Methods graph

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->Unique methods graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog Unique methods graph")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_unique_methods_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside Unique Methods graph, but found None"


def test_audit_log_unique_projects(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> Unique Projects graph

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->Unique projects graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog Unique Projects graph")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_unique_projects_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside Unique Projects graph, but found None"


def test_audit_log_unique_regions(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> Unique Regions graph

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->Unique Regions graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog Unique Regions graph")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_unique_regions_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside Unique Regions graph, but found None"


def test_audit_log_unique_resource_types(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> Unique Resource Types graph

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->Unique Resource Types graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog Unique Resource Types graph")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_unique_resource_type_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside Unique Resource Types graph, but found None"


def test_audit_log_user_details(api_v1_client, create_gcp_audit_log_events, gcp_creds, wait_for_auditlog_log):
    """Test case for GCP AuditLog Page -> User details dashboard

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog->User details graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
    """
    logger.info("Testing AuditLog User details dashboard")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = audit_log_helper.get_audit_log_user_details_by_project_id(gcp_project_id=gcp_creds['project_id'])
    assert data, "Expected to find data inside User details dashboard, but found None"


@pytest.mark.parametrize("expected_event", [
    "v1.compute.instances.delete",
    "v1.compute.instances.insert",
    "v1.compute.firewalls.insert",
    "v1.compute.firewalls.delete",
    "v1.compute.instances.stop"
])
def test_audit_log_logs(api_v1_client, create_gcp_audit_log_events, gcp_creds, expected_event, wait_for_auditlog_log):
    """Test case for GCP AuditLog logs

    Given: GCP AuditLog integration finished, GCP resources deployed and operated
    When: Check Cloud Logs->AuditLog
    Then: Expected Event Name should appear

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_gcp_audit_log_events: Deployed GCP resources
        gcp_creds: GCP account is being used
        expected_event: Expected Event_Name
    """
    logger.info(f"Testing {expected_event}...")
    resource_deploy_timestamp = create_gcp_audit_log_events['deployment_timestamp']
    gcp_instance_id = create_gcp_audit_log_events['gcp_instance_id']
    gcp_instance_name = create_gcp_audit_log_events['gcp_instance_name']
    gcp_firewall_name = create_gcp_audit_log_events['gcp_firewall_name']
    audit_log_helper = AuditLogHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    all_logs = audit_log_helper.get_audit_log_logs_by_gcp_project_id(gcp_project_id=gcp_creds['project_id'])
    found = False
    for log in all_logs:
        if log['METHOD_NAME'] == expected_event:
            if "instances" in expected_event and gcp_instance_name in log['RESOURCE_NAME'] and log['RESOURCE']['labels']['instance_id'] == gcp_instance_id:
                found = True
                break
            elif "firewall" in expected_event and gcp_firewall_name in log['RESOURCE_NAME']:
                found = True
                break
    assert found, f"Expected to find Event Name={expected_event} with correct resource ID/Name {create_gcp_audit_log_events}, but found nothing. Last collected logs: {json.dumps(all_logs, indent=2)}"
