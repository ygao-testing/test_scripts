import logging

from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


class CloudLogsHelper:
    def __init__(self, user_api, fix_timestamp: datetime = datetime.now()):
        self.user_api = user_api
        start_date = fix_timestamp - timedelta(hours=1)
        end_date = fix_timestamp + timedelta(hours=2)
        self.payload_template: dict[str, Any] = {
            "ParamInfo": {
                "StartTimeRange": int(start_date.timestamp() * 1000.0),
                "EndTimeRange": int(end_date.timestamp() * 1000.0)
            },
        }
        logger.info(f"CloudLogsHelper generic payload: {self.payload_template}")
