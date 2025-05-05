"""Vulnerabilities Host tests"""

import pytest


@pytest.mark.download
@pytest.mark.parametrize("delete_files", [{"prefix": "Host Vulnerabilit", "suffix": "csv"}], indirect=True)
def test_verify_vulnerabilities_host(ui, api_v1_client, delete_files):
    """
    Test Verify vulnerabilities host
    Oriole Test Cases:
        Host
        1204313 Open 'Vulnerabilities Host' page from the left menu
        1204314 Direct to the correct URL when clicking the left menu
        1204315 Left menu item should be active and highlighted when on the specified page
        1204316 [Dashboard] Show correct 'Scanned hosts' info in the Dashboard
        1204317 [Dashboard] Show correct 'MTTR' info in the Dashboard
        1204318 [Dashboard] Show correct 'Hosts with critical or high severities' info in the Dashboard
        1204319 [Dashboard] Show correct 'Hosts monitored by Code Aware Agent (CAA)' info in the Dashboard
        1204320 [Vulnerabilities] Show correct list of Vulnerabilities sorted by Host risk
        1204321 [Vulnerabilities] Show notification text if No data to display
        1204322 [Vulnerabilities] Initiate "Download Simplified CSV" from the list
        1204323 [Vulnerabilities] Initiate "Download Detailed CSV" from the list
        1204324 [Vulnerabilities] Show "Requested downloads" info in the left menu
        1204325 [Vulnerabilities] Show "CSV ready to download" notification on top right corner when downloading is ready
        1204326 [Vulnerabilities] Download Host Vulnerabilities CSV by clicking "Download now" in the notification
        1204327 [Vulnerabilities] Correct format and value in the downloaded "Host Vulnerabilities Simplified CSV"
        1204328 [Vulnerabilities] Correct format and value in the downloaded "Host Vulnerability Detailed CSV"
    """
    ui.vulnerabilities_host.verify_host_page(api_v1_client)
