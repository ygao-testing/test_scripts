"""GCP Audit Log tests"""


def test_verify_gcp_audit_log(ui):
    """
    Test Verify GCP audit log
    Oriole Test Cases:
        1203583 Open 'GCP Audit Log' page from the left menu
        1203584 Direct to the correct URL when clicking the left menu
        1203585 Left menu item should be active and highlighted when on the specified page
        1204114 Show onboarding notification text if GCP account set up is not finalized
        1204115 Show correct lists of Active High-Priority Alerts
        1204116 Show correct lists of Audit logs
        1204117 Show correct lists of User details
        1204118 Show correct lists of API error events
    """
    ui.gcp_audit_log.verify_gcp_audit_log_page()
