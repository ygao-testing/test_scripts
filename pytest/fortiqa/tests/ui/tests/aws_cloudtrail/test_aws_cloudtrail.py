"""AWS Cloud Trail tests"""


def test_verify_aws_cloudtrail(ui):
    """
    Test Verify AWS cloudtrail
    Oriole Test Cases:
        1203568 Open 'AWS Cloudtrail' page from the left menu
        1203569 Direct to the correct URL when clicking the left menu
        1203570 Left menu item should be active and highlighted when on the specified page
        1204102 Show onboarding notification text if AWS account set up is not finalized
        1204104 Show correct lists of Active High-Priority Alerts
        1204105 Show correct lists of CloudTrail logs
        1204106 Show correct lists of User details
        1204107 Show correct lists of User events
        1204108 Show correct lists of API error events
    """
    ui.aws_cloudtrail.verify_aws_cloudtrail_page()
