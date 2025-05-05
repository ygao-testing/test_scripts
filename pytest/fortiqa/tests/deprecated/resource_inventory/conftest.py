import pytest
from datetime import datetime, timedelta, timezone
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def time_filter():
    """
    This fixture return timeFilter as dictionary
    endTime as currenttime and startTime 1 day befor in UTC
    """
    # Get the current time in UTC
    current_utc_time = datetime.now(timezone.utc)

    # Calculate the last day time by subtracting one day from the current time
    last_day_utc_time = current_utc_time - timedelta(days=1)

    # Format the current time and the last day time in the desired format
    formatted_current_utc_time = current_utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    formatted_last_day_utc_time = last_day_utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "startTime": formatted_last_day_utc_time,
        "endTime": formatted_current_utc_time
    }
