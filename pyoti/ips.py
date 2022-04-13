import json
import requests
from typing import Dict

from pyoti.exceptions import SpamhausError
from pyoti.classes import IPAddress
from pyoti.utils import time_check_since_epoch


class AbuseIPDB(IPAddress):
    """AbuseIPDB IP Blacklist

    AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers,
    and abusive activity on the internet by providing a central blacklist to report and
    find IP addresses that have been associated with malicious activity.
    """
    def __init__(
        self, api_key: str, api_url: str = "https://api.abuseipdb.com/api/v2/check"
    ):
        """
        :param api_key: AbuseIPDB API key
        :param api_url: AbuseIPDB API URL
        """
        IPAddress.__init__(self, api_key, api_url)

    def _api_get(self, max_age: int) -> Dict:
        """
        :param max_age: How far back in time (days) to fetch reports. (defaults to 30 days)
        :return: dict of request response
        """
        params = {"ipAddress": self.ip, "maxAgeInDays": max_age}

        headers = {"Accept": "application/json", "Key": self.api_key}

        response = requests.request(
            "GET", url=self.api_url, headers=headers, params=params
        )

        return response.json()

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

        return response


class SpamhausIntel(IPAddress):
    """SpamhauzIntel IP Address Metadata

    SpamhausIntel is an API with metadata relating to compromised IP Addresses.
    """
    def __init__(
        self, api_key: str, api_url: str = "https://api.spamhaus.org/api/v1/login"
    ):
        """
        :param api_key: SpamhausIntel API key
        :param api_url: SPamhausIntel API URL
        """
        self._token: str = None
        self._expires: int = None
        IPAddress.__init__(self, api_key, api_url)

    def _api_login(self):
        """Authenticate to Spamhaus API to get bearer token"""
        data = {
            "username": self.api_key.split(":")[0],
            "password": self.api_key.split(":")[1],
            "realm": "intel",
        }

        response = requests.request("POST", url=self.api_url, data=json.dumps(data))

        if response.status_code == 200:
            self._token = response.json()["token"]
            self._expires = response.json()["expires"]
        elif response.status_code == 401:
            raise SpamhausError("Authentication Failed!")

    def _api_get(self, limit: int, since: int, until: int, type: str, ip: str, mask: str) -> requests.Response:
        """GET request to Spamhaus API

        :param limit: Constrain the number of rows returned by the query
        :param since: Results with a timestamp greater than or equal to 'since' (default 12 months if not passed)
        :param until: Results with a timestamp less than or equal to 'until' (default current timestamp if not passed)
        :param type: 'live' or 'history' return listings that are either active or inactive
        :param ip: IP address to look for
        :param mask: Optional netmask to use. (defaults to 32)
        :return: requests response
        """
        if not self._token:
            self._api_login()
        if not time_check_since_epoch(self._expires):
            self._api_login()

        headers = {"Authorization": f"Bearer {self._token}"}

        params = {"limit": limit, "since": since, "until": until}

        response = requests.request(
            "GET",
            url=f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/XBL/listed/{type}/{ip}/{mask}",
            headers=headers,
            params=params,
        )

        return response

    def check_ip(self, limit: int = None, since: int = None, until: int = None, type: str = "live", mask: str = "32") -> Dict:
        """Checks IP reputation

        :param limit: Constrain the number of rows returned by the query
        :param since: Results with a timestamp greater than or equal to 'since' (default 12 months if not passed)
        :param until: Results with a timestamp less than or equal to 'until' (default current timestamp if not passed)
        :param type: 'live' or 'history' return listings that are either active or inactive
        :param ip: IP address to look for
        :param mask: Optional netmask to use. (defaults to 32)
        :return: dict of request response
        """
        get = self._api_get(
            limit=limit, since=since, until=until, type=type, ip=self.ip, mask=mask
        )

        if get.status_code == 200 or get.status_code == 404:
            return get.json()
        else:
            raise SpamhausError(get.text)
