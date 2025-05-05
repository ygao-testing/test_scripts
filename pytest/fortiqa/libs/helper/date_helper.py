import logging
from datetime import datetime, timezone, timedelta, time
logger = logging.getLogger(__name__)


def datetime_to_iso8601(dt: datetime | None) -> str:
    """Convert a datetime object to ISO 8601 format with milliseconds, appending 'Z' for UTC.

    Args:
        dt (datetime | None): The datetime object to convert. If None, returns an empty string.

    Returns:
        str: The ISO 8601 formatted string (e.g., '2024-11-19T00:43:49.317Z') or an empty string if input is None.
    """
    if dt:
        return dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    return ""


def datetime_to_iso8601_preserve_original_precision(dt: datetime | None) -> str:
    """
    Convert a datetime object to ISO 8601 format, preserving original precision:
    - If the datetime has only seconds → format with seconds.
    - If it has microseconds ending in 000 → show milliseconds.
    - If it has full microseconds → include full microseconds.
    Appends 'Z' if the timezone is UTC.

    Args:
        dt (datetime | None): The datetime object to convert.

    Returns:
        str: ISO 8601 formatted string with original precision or empty string if None.
    """
    if not dt:
        return ""

    if dt.microsecond == 0:
        iso_str = dt.isoformat(timespec='seconds')
    elif dt.microsecond % 1000 == 0:
        iso_str = dt.isoformat(timespec='milliseconds')
    else:
        iso_str = dt.isoformat(timespec='microseconds')

    return iso_str.replace('+00:00', 'Z')


def datetime_to_timestamp(dt: datetime) -> int:
    """
    Convert a datetime object to a timestamp in milliseconds.

    Args:
        dt (datetime): The datetime object to convert.

    Returns:
        int: The corresponding timestamp in milliseconds.

    Example:
        >>> datetime_to_timestamp(datetime(2025, 2, 1, 12, 0, 0, tzinfo=timezone.utc))
        1738411200000
    """
    return int(dt.timestamp() * 1000)


def iso_to_timestamp(iso_string: str) -> int:
    """
    Convert an ISO 8601 formatted date-time string to a timestamp with milliseconds.

    Args:
        iso_string (str): The ISO 8601 formatted date-time string (e.g., "2025-02-01T12:00:00.000Z").

    Returns:
        int: The corresponding timestamp in milliseconds.

    Example:
        >>> iso_to_timestamp("2025-02-01T12:00:00.000Z")
        1738411200000
    """
    dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def timestamp_to_iso(timestamp_ms: int) -> str:
    """
    Convert a timestamp in milliseconds to an ISO 8601 formatted date-time string.

    Args:
        timestamp_ms (int): The timestamp in milliseconds.

    Returns:
        str: The corresponding ISO 8601 formatted date-time string (UTC).

    Example:
        >>> timestamp_to_iso(1738411200000)
        '2025-02-01T12:00:00.000Z'
    """
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def timestamp_to_datetime(timestamp_ms: int) -> datetime:
    """
    Convert a timestamp in milliseconds to a UTC datetime object.

    Args:
        timestamp_ms (int): The timestamp in milliseconds.

    Returns:
        datetime: The corresponding datetime object in UTC.

    Example:
        >>> timestamp_to_datetime(1738411200000)
        datetime.datetime(2025, 2, 1, 12, 0, tzinfo=datetime.timezone.utc)
    """
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)


def iso8601_to_datetime(iso_string: str) -> datetime:
    """
    Convert an ISO 8601 formatted date-time string to a datetime object.

    Args:
        iso_string (str): The ISO 8601 formatted date-time string (e.g., "2025-02-01T12:00:00.000Z").

    Returns:
        datetime: The corresponding datetime object in UTC.

    Example:
        >>> iso8601_to_datetime("2025-02-01T12:00:00.000Z")
        datetime.datetime(2025, 2, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    """
    return datetime.fromisoformat(iso_string.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)


def get_time_range_6_days_back_7am_to_next_day_659am_utc_epoch() -> dict[str, int]:
    """
    Returns a 7-day UTC time range as epoch milliseconds:
    - "StartTimeRange": 7 days before tomorrow at 07:00:00 UTC
    - "EndTimeRange": tomorrow at 06:59:59.999 UTC

    Logs ISO 8601 timestamps with 'Z' and epoch milliseconds using logger.debug.

    Returns:
        dict[str, int]: Dictionary with StartTimeRange and EndTimeRange in epoch milliseconds.
    """
    now = datetime.now(timezone.utc)

    # End time: tomorrow at 06:59:59.999 UTC
    tomorrow = now.date() + timedelta(days=1)
    end_time = datetime.combine(tomorrow, time(6, 59, 59, 999000), tzinfo=timezone.utc)

    # Start time: 7 days before end time, at 07:00:00 UTC
    start_time = datetime.combine((end_time - timedelta(days=7)).date(), time(7, 0, 0), tzinfo=timezone.utc)

    # Convert to epoch milliseconds
    start_epoch_ms = int(start_time.timestamp() * 1000)
    end_epoch_ms = int(end_time.timestamp() * 1000)

    # ISO8601 format with 'Z'
    start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Logging
    logger.debug(f"StartTimeRange UTC (ISO8601): {start_iso}")
    logger.debug(f"EndTimeRange UTC (ISO8601):   {end_iso}")
    logger.debug(f"StartTimeRange (epoch ms):    {start_epoch_ms}")
    logger.debug(f"EndTimeRange (epoch ms):      {end_epoch_ms}")

    return {
        "StartTimeRange": start_epoch_ms,
        "EndTimeRange": end_epoch_ms
    }
