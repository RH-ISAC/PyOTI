import time

from datetime import datetime, timedelta
from urllib.parse import urlsplit


def split_eml_domain(email: str) -> str:
    """Splits Domain from an Email Address"""
    return email.split("@")[1]


def split_url_domain(url: str) -> str:
    """Splits first level domain from an URL"""
    return urlsplit(url=url).netloc


def time_check_since_epoch(epoch: int) -> bool:
    seconds = epoch - int(time.time())
    hours = (seconds / 60) / 60
    if hours >= 1:
        return True
    else:
        return False


def epoch_to_date(epoch: int) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def time_since_seconds(seconds: int) -> str:
    return str(timedelta(seconds=seconds))
