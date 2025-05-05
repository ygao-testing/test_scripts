"""New Vulnerabilities tests"""

import pytest


@pytest.mark.parametrize("legacy", ["Hosts", "Container images"])
def test_switch_new_legacy_vulnerabilities_page(ui, legacy):
    """
    Test switch between New and Legacy Vulnerabilities page
    Oriole Test Cases:
        Overview
        1206411 Switch to "Host vulnerabilities" page by clicking "Switch to legacy vulnerability pages"
        1206412 Switch to "Container vulnerabilities" page by clicking "Switch to legacy vulnerability pages"
        Vulnerabilities Host
        1208332 Switch to "New vulnerabilities page" page by clicking "Switch to new vulnerability pages"
        Vulnerabilities Containers
        1208336 Switch to "New vulnerabilities page" page by clicking "Switch to new vulnerability pages"
    """
    ui.vulnerabilities_new_vuln.switch_new_legacy_vulnerabilities(legacy)


def test_verify_new_vulnerabilities_overview_tab(ui):
    """
    Test Verify new vulnerabilities Overview Tab
    Oriole Test Cases:
        Overview
        1206408 Open 'Vulnerabilities' page from the left menu
        1206409 Direct to the correct URL when clicking the left menu
        1206410 Left menu item should be active and highlighted when on the specified page
        1206413 [Total status over time] Show data in the past "1 week"
        1206414 [Total status over time] Show data in the past "30 Days"
        1206415 [Total status over time][Comparison of host vulnerabilities] Show correct data
        1206416 [Total status over time][Comparison of host vulnerabilities] Show correct tooltip
        1206417 [Total status over time][Comparison of container vulnerabilities] Show correct data
        1206418 [Total status over time][Comparison of container vulnerabilities] Show correct tooltip
        1206419 [Total status over time][Total at risk host vulnerabilities] Show correct data
        1206420 [Total status over time][Total at risk host vulnerabilities] Show correct tooltip
        1206421 [Total status over time][Total at risk container vulnerabilities] Show correct data
        1206422 [Total status over time][Total at risk container vulnerabilities] Show correct tooltip
        1206423 [Trend] Show data in the past "1 week"
        1206424 [Trend] Show data in the past "30 Days"
        1206425 [Trend][Host vulnerabilities over time] Show correct data
        1206426 [Trend][Host vulnerabilities over time] Show correct tooltip
        1206427 [Trend][Container vulnerabilities over time] Show correct data
        1206428 [Trend][Container vulnerabilities over time] Show correct tooltip
        1206431 [Top Items][Top vulnerable container images] Show correct tooltip
        1206436 [Top Items][Top vulnerable hosts] Show correct tooltip
        1206441 [Top Items][Top vulnerabilities by impacted hosts] Show correct tooltip
        1206446 [Top Items][Top vulnerabilities by impacted images] Show correct tooltip
        1206451 [Top Items][Top fixable packages in containers] Show correct tooltip
        1206456 [Top Items][Top fixable packages in hosts] Show correct tooltip
        1209656 [Top Items][Most recent vulnerable hosts] Show correct tooltip
        1209733 [Top Items][Most recent vulnerable container images] Show correct tooltip
        1206460 [Latest status][Unscanned images with active containers] Show correct data
        1206461 [Latest status][Unscanned images with active containers] Show correct tooltip
        1206462 [Latest status][Latest at risk container images] Show correct data
        1206463 [Latest status][Latest at risk container images] Show correct tooltip
        1206464 [Latest status][Latest at risk hosts] Show correct data
        1206465 [Latest status][Latest at risk hosts] Show correct tooltip
        1206466 [Latest status][Host coverage type] Show correct data
        1206467 [Latest status][Host coverage type] Show correct tooltip
        1208616 [Latest status][OS EOL dates] Show correct data
        1208617 [Latest status][OS EOL dates] Show correct tooltip
        1206468 [Trends by resource groups] Show data in the past "1 week"
        1206469 [Trends by resource groups] Show data in the past "30 Days"
        1206470 [Trends by resource groups][Host vulnerabilities at risk] Show correct data
        1206471 [Trends by resource groups][Host vulnerabilities at risk] Show notification text if No data to display
        1206472 [Trends by resource groups][Host vulnerabilities at risk] Show correct tooltip
        1206473 [Trends by resource groups][Container vulnerabilities at risk] Show correct data
        1206474 [Trends by resource groups][Container vulnerabilities at risk] Show notification text if No data to display
        1206475 [Trends by resource groups][Container vulnerabilities at risk] Show correct tooltip
    """
    ui.vulnerabilities_new_vuln.verify_overview_tab()


# TODO: split test_verify_new_vulnerabilities_top_items_tab into 4-5 separate test cases.
@pytest.mark.download
@pytest.mark.parametrize("delete_files", [{"prefix": "", "suffix": "csv"}], indirect=True)
@pytest.mark.parametrize("widget", ["Top vulnerable container images", "Top vulnerable hosts",
                                    "Top vulnerabilities by impacted hosts",
                                    "Top vulnerabilities by impacted images", "Top fixable packages in containers",
                                    "Top fixable packages in hosts", "Most recent vulnerable hosts",
                                    "Most recent vulnerable container images"])
def test_verify_new_vulnerabilities_top_items_tab(ui, delete_files, widget):
    """
    Test Verify new vulnerabilities Top Items tab
    Oriole Test Cases:
        Overview
        1206430 [Top Items][Top vulnerable container images] Show correct data
        1206432 [Top Items][Top vulnerable container images] Initiate Downloading CSV from the list
        1206433 [Top Items][Top vulnerable container images] Show "CSV ready to download" notification on top right corner when downloading is ready
        1206434 [Top Items][Top vulnerable container images] Correct format and value in the downloaded "Container images.csv"
        1206435 [Top Items][Top vulnerable hosts] Show correct data
        1206437 [Top Items][Top vulnerable hosts] Initiate Downloading CSV from the list
        1206438 [Top Items][Top vulnerable hosts] Show "CSV ready to download" notification on top right corner when downloading is ready
        1206439 [Top Items][Top vulnerable hosts] Correct format and value in the downloaded "Hosts.csv"
        1206440 [Top Items][Top vulnerabilities by impacted hosts] Show correct data
        1206442 [Top Items][Top vulnerabilities by impacted hosts] Initiate Downloading CSV from the list
        1206443 [Top Items][Top vulnerabilities by impacted hosts] Show "CSV ready to download" notification on top right corner when downloading is ready
        1206444 [Top Items][Top vulnerabilities by impacted hosts] Correct format and value in the downloaded "Vulnerabilities.csv"
        1206445 [Top Items][Top vulnerabilities by impacted images] Show correct data
        1206447 [Top Items][Top vulnerabilities by impacted images] Initiate Downloading CSV from the list
        1206448 [Top Items][Top vulnerabilities by impacted images] Show "CSV ready to download" notification on top right corner when downloading is ready
        1206449 [Top Items][Top vulnerabilities by impacted images] Correct format and value in the downloaded "Vulnerabilities.csv"
        1206450 [Top Items][Top fixable packages in containers] Show correct data
        1206452 [Top Items][Top fixable packages in containers] Initiate Downloading CSV from the list
        1206453 [Top Items][Top fixable packages in containers] Show "CSV ready to download" notification on top right corner when downloading is ready
        1206454 [Top Items][Top fixable packages in containers] Correct format and value in the downloaded "Package Instances.csv"
        1206455 [Top Items][Top fixable packages in hosts] Show correct data
        1206457 [Top Items][Top fixable packages in hosts] Initiate Downloading CSV from the list
        1206458 [Top Items][Top fixable packages in hosts] Show "CSV ready to download" notification on top right corner when downloading is ready
        1206459 [Top Items][Top fixable packages in hosts] Correct format and value in the downloaded "Package Instances.csv"
        1209655 [Top Items][Most recent vulnerable hosts] Show correct data
        1209657 [Top Items][Most recent vulnerable hosts] Initiate Downloading CSV from the list
        1209658 [Top Items][Most recent vulnerable hosts] Show "CSV ready to download" notification on top right corner when downloading is ready
        1209659 [Top Items][Most recent vulnerable hosts] Correct format and value in the downloaded "Hosts.csv"
        1209732 [Top Items][Most recent vulnerable container images] Show correct data
        1209734 [Top Items][Most recent vulnerable container images] Initiate Downloading CSV from the list
        1209735 [Top Items][Most recent vulnerable container images] Show "CSV ready to download" notification on top right corner when downloading is ready
        1209736 [Top Items][Most recent vulnerable container images] Correct format and value in the downloaded "Container images.csv"
        1213194 [Top Items] Show the full Top Items list in the 'Explore' page by clicking "View more" button
        1210184 [Top Items] Full Top Items list in the Explore page should be consistent
        1213539 Hide the Widget section on the top by clicking "Hide"
    """
    ui.vulnerabilities_new_vuln.verify_top_items_tab(widget)


# Explore #
@pytest.mark.skip(reasons="Not ready since UI changed. https://lacework.atlassian.net/browse/FORTIQA-403")
@pytest.mark.download
@pytest.mark.parametrize("delete_files", [{"prefix": "", "suffix": "csv"}], indirect=True)
@pytest.mark.parametrize("show",
                         ["Vulnerabilities", "Hosts", "Packages", "Container images", "Unique vulnerabilities by host",
                          "Unique vulnerabilities by container image"])
def test_verify_new_vulnerabilities_explore_tab(ui, delete_files, show):
    """
    Test Verify new vulnerabilities Explore Tab
    Oriole Test Cases:
        Explore
        1210277 Show all Hosts
        1210295 Show all Vulnerabilities
        1210296 Show all Packages
        1206969 Show all Container images
        1210298 Show all Unique vulnerabilities by host
        1210299 Show all Unique vulnerabilities by container image
        1210272 "Clear query" button
        1210273 "Cancel" button
        1210274 "Search" button
        1206482 Show correct query results
        1206483 Refresh button
        1206484 Initiate Downloading "Table CSV" from the list
        1206486 Show "CSV ready to download" notification on top right corner when downloading is ready
        1206487 Correct format and value in the downloaded "Table CSV"
        1206489 Display a particular number of lines
    """
    ui.vulnerabilities_new_vuln.verify_explore_tab(show)
