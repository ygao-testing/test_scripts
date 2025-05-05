"""Explorer tests"""
import pytest
import random

saved_query_names = [
    "Show all hosts with log4j vulnerability",
    "Show all hosts with vulnerability related to xz-utils package",
    "Show all hosts exposed to the internet and running active packages with critical or high severity vulnerabilities",
    "Show high risk hosts with SSH port open and exposed to the public internet due to inbound access",
    "Show all AWS identities that can access storage assets",
    "Show all hosts that are internet exposed to a specific CIDR range behind a VPN or other gateways",
    "Show all storage assets of type AWS accessible via identity",
    "Show all hosts that may lead to lateral movement because of SSH keys"
]


# Landing
@pytest.mark.parametrize("saved_queries", [random.choice(saved_query_names)])  # type: ignore
def test_select_saved_queries_from_landing_link(ui, saved_queries):
    """
    Test Saved Queries links on Landing page
    Oriole Test Cases:
        Landing
        1203720 Open 'Explorer' page from the left menu
        1203721 Direct to the correct URL when clicking the left menu
        1203722 Left menu item should be active and highlighted when on the specified page
        1205271 Direct to the Landing page by clicking "Landing" tab on the top
        1182612 Verify text messages on Landing page
        1182614 Direct to the saved query by clicking the quick links on Landing page
    """
    ui.explorer.verify_query(tab="Landing", saved_query_name=saved_queries)


def test_build_your_own_query_button(ui):
    """
    Test "Build your own query" button on Landing page
    Oriole Test Cases:
        Landing
        1182613 Direct to the Graph page by clicking the "Build your own query" on Landing page
    """
    ui.explorer.build_your_own_query_button()


# Graph
@pytest.mark.parametrize("saved_queries", saved_query_names)  # type: ignore
def test_select_saved_queries_from_graph(ui, saved_queries):
    """
    Test search Saved Queries on Graph page
    Oriole Test Cases:
        Graph
        1205272 Direct to the Graph page by clicking "Graph" tab on the top
        1205275 "Clear query" button
        1182616 Search for a query that is in the list
        1182619 Compare GUI and API data of a query (right part)
        1182622 "Apply query" button
        1204330 Correct saved query details applied to the Search
        1204331 "Search" button
        1204332 Show correct lists of Query results sorted by Risk Score
    """
    ui.explorer.verify_query(tab="Graph", saved_query_name=saved_queries)


# TODO: verify saved query from the Landing page

custom_query_data = {
    "return_type": "Hosts",
    "clauses": [
        {
            "name": "Risk",
            "subname": "Score",
            "limits_name": "is greater than",
            "limits_value": "0",
        },
    ]
}


@pytest.mark.skip(reason="Custom Query Not ready")  # type: ignore
def test_explorer_custom_queries(ui):
    """Test Explorer Custom Queries"""
    ui.explorer.verify_query(custom_query_data=custom_query_data)
