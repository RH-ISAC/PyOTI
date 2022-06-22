import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import IPAddress


class GreyNoise(IPAddress):
    """GreyNoise

    GreyNoise produces two datasets of IP information that can be used for threat enrichment. GreyNoise’s internet-wide
    sensor network passively collects packets from hundreds of thousands of IPs seen scanning the internet every day.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.greynoise.io"):
        """
        :param api_key: GreyNoise API key
        :param api_url: GreyNoise base API URL
        """
        IPAddress.__init__(self, api_key, api_url)

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API"""
        headers = {
            "Accept": "application/json",
            "key": self.api_key,
            "User-Agent": f"PyOTI/ {__version__}"
        }

        response = requests.request("GET", url=url, headers=headers)

        return response

    def check_ip_community(self) -> Dict:
        """Check IP reputation

        The Community API provides community users with a free tool to query IPs in the GreyNoise dataset and retrieve
        a subset of the full IP context data returned by the IP Lookup API.
        """
        url = f"{self.api_url}/v3/community/{self.ip}"
        response = self._api_get(url=url)

        return response.json()

    def check_ip_quick(self) -> Dict:
        """ Check IP reputation

        Requires premium API key.

        Check whether a given IP address is “Internet background noise”, or has been observed scanning or attacking
        devices across the Internet.
        """
        url = f"{self.api_url}/v2/noise/quick/{self.ip}"
        response = self._api_get(url=url)

        codes = {
            "0x00": "IP hasn't been observed scanning the internet.",
            "0x01": "IP has been observed by GreyNoise sensor network.",
            "0x02": "IP has been observed scanning GreyNoise sensor network, but hasn't completed a full connection, "
                    "meaning this can be spoofed.",
            "0x03": "IP is adjacent to another host that has been directly observed by GreyNoise sensor network.",
            "0x04": "Reserved.",
            "0x05": "IP is commonly spoofed in internet-scan activity.",
            "0x06": "IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled.",
            "0x07": "IP is invalid.",
            "0x08": "IP was classified as noise, but has not been observed engaging in internet-wide scans or attacks "
                    "in over 90 days.",
            "0x09": "IP was found in RIOT.",
            "0x10": "IP has been observed by GreyNoise sensor network and was found in RIOT."
        }

        r = response.json()
        r_code = r.get("code")
        r['code_message'] = codes.get(r_code)

        return r

    def check_ip_context(self) -> Dict:
        """ Check IP reputation

        Requires premium API key.

        Get more information about a given IP address. Returns time ranges, IP metadata (network owner, ASN, reverse
        DNS pointer, country), associated actors, activity tags, and raw port scan and web request information.
        """
        url = f"{self.api_url}/v2/noise/context/{self.ip}"
        response = self._api_get(url=url)

        return response.json()

    def check_ip_riot(self) -> Dict:
        """ Check IP reputation

        Requires premium API key.

        RIOT identifies IPs from known benign services and organizations that commonly cause false positives in network
        security and threat intelligence products. The collection of IPs in RIOT is continually curated and verified to
        provide accurate results.
        """
        url = f"{self.api_url}/v2/riot/{self.ip}"
        response = self._api_get(url=url)

        return response.json()
