import requests
from typing import Dict, List

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

    def _api_post(self, url: str, ip_list: List[str]) -> requests.models.Response:
        """POST request to API"""
        payload = {"ips": ip_list}

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "key": self.api_key,
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("POST", url=url, json=payload, headers=headers)

        return response

    def check_ip_community(self) -> Dict:
        """Check IP reputation community

        The Community API provides community users with a free tool to query IPs in the GreyNoise dataset and retrieve
        a subset of the full IP context data returned by the IP Lookup API.
        """
        url = f"{self.api_url}/v3/community/{self.ip}"
        response = self._api_get(url=url)

        return response.json()

    def bulk_check_ips(self, ips : List[str], quick: bool = True) -> Dict:
        """Bulk Check IP reputation

        :param ips: List of IPs to check reputation
        :param quick: If false, return full reputation
        """
        if quick:
            url = f"{self.api_url}/v3/ip?quick=true"
        else:
            url = f"{self.api_url}/v3/ip/{self.ip}"

        response = self._api_post(url=url, ip_list=ips)

        return response.json()

    def check_ip(self, quick: bool = True) -> Dict:
        """ Check IP reputation

        :param quick: If false, return full reputation
        """
        if quick:
            url = f"{self.api_url}/v3/ip/{self.ip}?quick=true"
        else:
            url = f"{self.api_url}/v3/ip/{self.ip}"
        response = self._api_get(url=url)

        return response.json()
