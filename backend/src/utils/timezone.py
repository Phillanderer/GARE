"""
Timezone utilities for the GARE pipeline.

Internal storage always uses UTC. User-facing display converts to
the timezone specified by the DISPLAY_TIMEZONE environment variable.
"""

import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def format_display(dt: datetime = None, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
    """Format a datetime for user-facing display in the configured local timezone.

    Args:
        dt: A datetime to format. If None, uses current UTC time.
            Naive datetimes are assumed to be UTC.
        fmt: strftime format string.

    Returns:
        Formatted string in the display timezone.
    """
    if dt is None:
        dt = utc_now()
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    tz_name = os.environ.get("DISPLAY_TIMEZONE", "UTC")
    try:
        local_dt = dt.astimezone(ZoneInfo(tz_name))
    except (KeyError, Exception):
        local_dt = dt  # Fall back to UTC if timezone name is invalid
    return local_dt.strftime(fmt)
