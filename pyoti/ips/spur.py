import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import IPAddress


class SpurIPIntel(IPAddress):
    """SpurIPIntel

    Spur is an IP intelligence company committed to truth and transparency. We reveal the hidden infrastructure
    behind global internet traffic — VPNs, proxies, mobile gateways, botnets, and anonymized services — enabling
    organizations to distinguish legitimate users from hidden threats.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.spur.us"):
        """
        :param api_key: Spur API key
        :param api_url: Spur base API URL
        """
        IPAddress.__init__(self, api_key, api_url)

    def _api_get(self, url: str, **params) -> requests.models.Response:
        """GET request to Spur API"""
        headers = {
            "Token": self.api_key,
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("GET", url=url, headers=headers, params=params)

        return response

    def check_ip(self, mmgeo: bool = None) -> Dict:
        """Check IP context

        Retrieves an IP Context Object by IPv4 or IPv6 address. An IP Context Object summarizes all available
        information about the queried IP address. Some fields are optional and will be omitted if not available.

        :param mmgeo: If true, return MaxMind's GeoLite2 geolocation data instead of Spur's geolocation data in the location object.
        """
        params = {}
        if mmgeo:
            params["mmgeo"] = 1
        url = f"{self.api_url}/v2/context/{self.ip}"
        response = self._api_get(url, **params)

        return response.json()

    def check_ip_historical(self, datetime: str, mmgeo: bool = None) -> Dict:
        """Check IP historical data

        Retrieves an IP Context Object by IPv4 or IPv6 address for the specified date. An IP Context Object
        summarizes all available information about the queried IP address. Some fields are optional and will
        be omitted if not available.

        ** Note: this endpoint is only available for Enterprise plans with historical access

        :param datetime: Specific date to check IP against (YYYYmmdd)
        :param mmgeo: If true, return MaxMind's GeoLite2 geolocation data instead of Spur's geolocation data in the location object.
        """
        params = {
            "dt": datetime,
        }
        if mmgeo:
            params["mmgeo"] = 1
        url = f"{self.api_url}/v2/context/{self.ip}"
        response = self._api_get(url, **params)

        return response.json()

    def lookup_tag_metadata(self, tag: str) -> Dict:
        """Look up tag metadata

        Retrieves a Tag Metadata Object which contains a summary of metrics and information for the provided tag.

        :param tag: Tag name
        """
        url = f"{self.api_url}/v2/metadata/tags/{tag}"
        response = self._api_get(url)

        return response.json()

    def lookup_api_token_status(self) -> Dict:
        """Look up API token status

        Retrieves the status of your API token, the number of queries remaining for your billing period, and your
        service tier.
        """
        url = f"{self.api_url}/status"
        response = self._api_get(url)

        return response.json()
