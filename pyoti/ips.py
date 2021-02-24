import json
import requests

from pyoti.exceptions import SpamhausError
from pyoti.classes import IPAddress
from pyoti.keys import abuseipdb, spamhausintel
from pyoti.utils import time_check_since_epoch


class AbuseIPDB(IPAddress):
    """AbuseIPDB IP Blacklist

    AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers,
    and abusive activity on the internet by providing a central blacklist to report and
    find IP addresses that have been associated with malicious activity.

    :param api_key: AbuseIPDB API key
    :param api_url: AbuseIPDB API URL
    """

    def __init__(
        self, api_key=abuseipdb, api_url="https://api.abuseipdb.com/api/v2/check"
    ):
        IPAddress.__init__(self, api_key, api_url)

    def _api_get(self, max_age):
        params = {"ipAddress": self.ip, "maxAgeInDays": max_age}

        headers = {"Accept": "application/json", "Key": self.api_key}

        response = requests.request(
            "GET", url=self.api_url, headers=headers, params=params
        )

        return response.json()

    def check_ip(self, max_age=30):
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
        self, api_key=spamhausintel, api_url="https://api.spamhaus.org/api/v1/login"
    ):
        self._token = None
        self._expires = None
        IPAddress.__init__(self, api_key, api_url)

    def _api_login(self):
        data = {
            "username": spamhausintel.split(":")[0],
            "password": spamhausintel.split(":")[1],
            "realm": "intel",
        }

        response = requests.request("POST", url=self.api_url, data=json.dumps(data))

        if response.status_code == 200:
            self._token = response.json()["token"]
            self._expires = response.json()["expires"]
        elif response.status_code == 401:
            raise SpamhausError("Authentication Failed!")

    def _api_get(self, limit, since, until, type, ip, mask):
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

    def check_ip(self, limit=None, since=None, until=None, type="live", mask="32"):
        """
        :param limit: default None
        :param since: default 12 months ago (unix timestamp)
        :param until: default current time (unix timestamp)
        :param type: default live (history - other option)
        :param ip: IP Address to check reputation
        :param mask: default 32
        :return: dict
        """

        get = self._api_get(
            limit=limit, since=since, until=until, type=type, ip=self.ip, mask=mask
        )

        if get.status_code == 200:
            return get.json()
        elif get.status_code == 404:
            return "Not found!"
        else:
            raise SpamhausError(get.text)
