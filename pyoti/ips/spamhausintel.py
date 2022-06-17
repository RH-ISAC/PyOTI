import json
import requests
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import IPAddress
from pyoti.exceptions import SpamhausIntelError
from pyoti.utils import time_check_since_epoch


class SpamhausIntel(IPAddress):
    """SpamhauzIntel IP Address Metadata

    SpamhausIntel is an API with metadata relating to compromised IP Addresses.
    """
    def __init__(
        self, api_key: str, api_url: str = "https://api.spamhaus.org/api"
    ):
        """
        :param api_key: SpamhausIntel API key
        :param api_url: SPamhausIntel base API URL
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

        headers = {"User-Agent": f"PyOTI {__version__}"}

        response = requests.request("POST", url=f"{self.api_url}/v1/login", data=json.dumps(data), headers=headers)

        if response.status_code == 200:
            self._token = response.json()["token"]
            self._expires = response.json()["expires"]
        elif response.status_code == 401:
            raise SpamhausIntelError("Authentication Failed!")

    def _api_get(self, limit: Optional[int], since: Optional[int], until: Optional[int], type: str, ip: str, mask: str) -> requests.models.Response:
        """GET request to Spamhaus API

        :param limit: Constrain the number of rows returned by the query
        :param since: Results with a timestamp greater than or equal to 'since' (default 12 months if not passed)
        :param until: Results with a timestamp less than or equal to 'until' (default current timestamp if not passed)
        :param type: 'live' or 'history' return listings that are either active or inactive
        :param ip: IP address to look for
        :param mask: Optional netmask to use. (defaults to 32)
        """
        if not self._token:
            self._api_login()
        if not time_check_since_epoch(self._expires):
            self._api_login()

        headers = {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": f"PyOTI {__version__}"
        }

        params = {"limit": limit, "since": since, "until": until}

        response = requests.request(
            "GET",
            url=f"{self.api_url}/intel/v1/byobject/cidr/XBL/listed/{type}/{ip}/{mask}",
            headers=headers,
            params=params,
        )

        return response

    def check_ip(
            self,
            limit: Optional[int] = None,
            since: Optional[int] = None,
            until: Optional[int] = None,
            type: str = "live",
            mask: str = "32"
    ) -> Dict:
        """Checks IP reputation

        :param limit: Constrain the number of rows returned by the query
        :param since: Results with a timestamp greater than or equal to 'since' (default 12 months if not passed)
        :param until: Results with a timestamp less than or equal to 'until' (default current timestamp if not passed)
        :param type: 'live' or 'history' return listings that are either active or inactive
        :param mask: Optional netmask to use. (defaults to 32)
        :return: dict of request response
        """
        response = self._api_get(
            limit=limit, since=since, until=until, type=type, ip=self.ip, mask=mask
        )

        if response.status_code == 200 or response.status_code == 404:
            return response.json()
        else:
            raise SpamhausIntelError(response.text)
