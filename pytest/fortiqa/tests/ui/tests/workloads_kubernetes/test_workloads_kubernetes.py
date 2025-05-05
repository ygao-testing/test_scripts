"""Workloads Kubernetes tests"""


def test_verify_workloads_kubernetes(ui):
    """
    Test Verify workloads Kubernetes
    Oriole Test Cases:
        1203568 Open 'Workloads Kubernetes' page from the left menu
        1203569 Direct to the correct URL when clicking the left menu
        1203570 Left menu item should be active and highlighted when on the specified page
    """
    ui.workloads_kubernetes.verify_workloads_kubernetes_page()
