import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import IPAddress


class AbuseIPDB(IPAddress):
    """AbuseIPDB IP Blacklist

    AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers,
    and abusive activity on the internet by providing a central blacklist to report and
    find IP addresses that have been associated with malicious activity.
    """
    def __init__(
        self, api_key: str, api_url: str = "https://api.abuseipdb.com/api/v2"
    ):
        """
        :param api_key: AbuseIPDB API key
        :param api_url: AbuseIPDB base API URL
        """
        IPAddress.__init__(self, api_key, api_url)

    def _api_get(self, max_age: int) -> requests.models.Response:
        """
        :param max_age: How far back in time (days) to fetch reports. (defaults to 30 days)
        """
        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
            "User-Agent": f"PyOTI {__version__}"
        }

        params = {"ipAddress": self.ip, "maxAgeInDays": max_age}

        response = requests.request(
            "GET", url=f"{self.api_url}/check", headers=headers, params=params
        )

        return response

    def check_ip(self, max_age: int = 30) -> Dict:
        """
        Checks IP reputation

        The check endpoint (api.abuseipdb.com/api/v2/check) accepts a single IP
        address (v4 or v6). Optionally you may set the max_age parameter to only
        return reports within the last X number of days.

        :param max_age: How far back in time (days) to fetch reports. (defaults to 30 days)
        :return: dict
        """
        response = self._api_get(max_age=max_age)

        return response.json()
