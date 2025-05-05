"""Attack Path Top Work Items tests"""


def test_verify_top_work_items(ui):
    """
    Test Verify top work items
    Oriole Test Cases:
        1203562 Open 'Top Work items' page from the left menu
        1203563 Direct to the correct URL when clicking the left menu
        1203564 Left menu item should be active and highlighted When on the specified page
    """
    ui.top_work_items.verify_top_work_items_page()
