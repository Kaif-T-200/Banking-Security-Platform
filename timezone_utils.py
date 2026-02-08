from datetime import datetime
import pytz
from typing import Optional, Union
UTC = pytz.UTC
IST = pytz.timezone('Asia/Kolkata')
DEFAULT_FORMAT = '%d-%m-%Y %H:%M:%S'
class TimezoneConverter:
    @staticmethod
    def to_ist(dt: Optional[Union[datetime, str]],
               format_str: Optional[str] = None) -> Optional[str]:
        if dt is None:
            return None
        format_str = format_str or DEFAULT_FORMAT
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                return dt
        if not isinstance(dt, datetime):
            return None
        if dt.tzinfo is None:
            dt = UTC.localize(dt)
        ist_time = dt.astimezone(IST)
        return ist_time.strftime(format_str)
    @staticmethod
    def to_ist_datetime(dt: Optional[Union[datetime, str]]) -> Optional[datetime]:
        if dt is None:
            return None
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                return None
        if not isinstance(dt, datetime):
            return None
        if dt.tzinfo is None:
            dt = UTC.localize(dt)
        return dt.astimezone(IST)
    @staticmethod
    def time_ago(dt: Optional[Union[datetime, str]]) -> Optional[str]:
        if dt is None:
            return None
        ist_dt = TimezoneConverter.to_ist_datetime(dt)
        if ist_dt is None:
            return None
        now = datetime.now(IST)
        diff = now - ist_dt
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return f"{seconds}s ago"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes}m ago"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours}h ago"
        elif seconds < 604800:
            days = seconds // 86400
            return f"{days}d ago"
        else:
            return ist_dt.strftime(DEFAULT_FORMAT)
    @staticmethod
    def get_current_ist() -> datetime:
        return datetime.now(IST)
def format_ist(dt: Optional[Union[datetime, str]],
               format_str: Optional[str] = None) -> Optional[str]:
    return TimezoneConverter.to_ist(dt, format_str)
def format_ist_time_ago(dt: Optional[Union[datetime, str]]) -> Optional[str]:
    return TimezoneConverter.time_ago(dt)
