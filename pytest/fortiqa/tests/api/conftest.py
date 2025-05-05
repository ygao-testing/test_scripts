import logging
import pytest

from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


@pytest.fixture
def list_all_query_cards(api_v1_client):
    """Fixture to list all query cards"""
    query_card = QueryCard(api_v1_client)
    all_cards_info = query_card.get_all_query_cards()
    all_cards_names = list(all_cards_info.json()['data'].keys())
    logger.info(f"All query cards: {all_cards_names}")
    return all_cards_names
