"""Alerts tests"""
import pytest


@pytest.mark.sanity
def test_verify_alerts_page(ui):
    """
    Verify Alerts page:
    1. Open 'Alerts' page.
    2. Get "Overview" data.
    3. Get "Alert Details" data:
        3.1 Verify Alert lists
        3.2 Verify the first alert
    Oriole Test Cases:
        1203565 Open 'Alerts' page from the left menu
        1203566 Direct to the correct URL when clicking the left menu
        1203567 Left menu item should be active and highlighted when on the specified page
        1204073 Show correct 'Total alerts by severity' info in the Overview
        1204074 Show correct lists of alerts sorted by time
        1204075 Go to alert Details by clicking each alert in the list
        1204076 Basic info in the Details page should keep in line with alert lists
        1204077 "Why" in the Details page should keep in line with alert lists
        1204078 "When" in the Details page should keep in line with alert lists
        1204079 Show correct "Who" in the Details page
        1204080 Show correct "What" in the Details page
        1204081 Show correct "Where" in the Details page
        1204082 Show correct events list in the Events page
        1204083 Show correct integration info in the Integrations page
        1204084 Show correct comments in the Comments page
        1204085 Show correct exposure in the Exposure page
        1204086 Show correct Investigation questions in the Investigation page
        1204087 Show correct remediation questions in the Remediation page
        1204088 Show correct related alerts list in the Related Alerts page
    """
    ui.alerts.verify_alerts_page()


@pytest.mark.skip(reason="New dashboard remove the Alert overview link")
@pytest.mark.parametrize("severity", ["Critical", "High", "Medium", "Low", "Info"])
def test_verify_alerts_form_dashboard_by_severity(ui, severity):
    """
    Verify Alerts page by severity and compare with dashboard:
    1. Get 'Alert overview' data from 'Dashboard'.
    2. Go to 'Alerts' page by clicking link in a dashboard widget and verify page.
    """
    ui.alerts.verify_alerts_form_dashboard_by_severity(severity)
