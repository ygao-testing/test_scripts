"""Vulnerabilities Containers tests"""


def test_verify_vulnerabilities_containers_page(ui):
    """
    Test Verify Vulnerabilities Containers page
    Oriole Test Cases:
        1208333 Open 'Vulnerabilities Containers' page from the left menu
        1208334 Direct to the correct URL when clicking the left menu
        1208335 Left menu item should be active and highlighted when on the specified page
    """
    ui.vulnerabilities_containers.verify_vulnerabilities_containers_page()
