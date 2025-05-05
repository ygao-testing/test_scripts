"""Resource Inventory tests"""


def test_verify_resource_inventory(ui):
    """
    Test Verify resource inventory
    Oriole Test Cases:
        1203580 Open 'Resource Inventory' page from the left menu
        1203581 Direct to the correct URL when clicking the left menu
        1203582 Left menu item should be active and highlighted when on the specified page
        1204119 In Default view, Show correct lists of resources sorted by Resource ID
    """
    ui.resource_inventory.verify_resource_inventory_page()
