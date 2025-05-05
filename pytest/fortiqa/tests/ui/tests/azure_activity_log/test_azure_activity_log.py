"""Azure Activity Log tests"""


def test_verify_azure_activity_log(ui):
    """
    Test Verify Azure activity log
    Oriole Test Cases:
        1203639 Open 'Azure Activity Log' page from the left menu
        1203640 Direct to the correct URL when clicking the left menu
        1203641 Left menu item should be active and highlighted when on the specified page
        1204109 Show onboarding notification text if Azure account set up is not finalized
        1204110 Show correct lists of Active High-Priority Alerts
        1204111 Show correct lists of Activity logs
        1204112 Show correct lists of User details
        1204113 Show correct lists of API error events
    """
    ui.azure_activity_log.verify_azure_activity_log_page()
