"""Dashboard tests"""
import pytest


@pytest.mark.skip(reason="This tests is for old Dashboard")
def test_verify_dashboard_page(ui):
    """
    API responses:
    Table "Top identity risks" - API Dashboard_IdentityDetails
    Table "Top non-compliant resources" - API Dashboard_ComplianceDetailsByResource
    Table "Top vulnerable hosts" - API Dashboard_HostVulnsDetails
    """
    ui.dashboard.verify_dashboard_page()
