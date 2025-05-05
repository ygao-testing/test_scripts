"""Workloads Containers tests"""


def test_verify_workloads_containers(ui):
    """
    Test Verify Workloads containers
    Oriole Test Cases:
        1203577 Open 'Workloads Containers' page from the left menu
        1203578 Direct to the correct URL when clicking the left menu
        1203579 Left menu item should be active and highlighted when on the specified page
        1204301 Show correct lists of Alerts
        1204302 Show correct lists of List of active containers
        1204303 Show correct lists of Container image information
        1204304 Show correct lists of Command line by executable
        1204305 Show correct lists of Active listening ports
    """
    ui.workloads_containers.verify_workloads_containers_page()
