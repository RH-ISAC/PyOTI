import requests
from typing import Dict, List, Union

from pyoti import __version__
from pyoti.classes import Domain, IPAddress


class IP2WHOIS(Domain):
    """IP2WHOIS domain WHOIS

    IP2WHOIS Domain WHOIS API helps users to obtain domain information and WHOIS record by using a domain name. The
    WHOIS API returns a comprehensive WHOIS data such as creation date, updated date, expiration date, domain age, the
    contact information of the registrant, mailing address, phone number, email address, nameservers the domain is
    using and much more.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.ip2whois.com/v2"):
        """
        :param api_key: IP2Location.io API key
        :param api_url: IP2WHOIS API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, domain: str) -> requests.models.Response:
        """GET request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {
            'domain': domain,
            'format': 'json',
            'key': self.api_key
        }

        response = requests.request("GET", url=self.api_url, headers=headers, params=params)

        return response

    def check_domain(self) -> Union[Dict, str]:
        """Checks Domain WHOIS"""
        response = self._api_get(self.domain)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            return response.json()['error']['error_message']


class IP2Location(IPAddress):
    """IP2Location IP Geolocation

    IP2Location.io provides RESTful API allowing users to check IP address location in real time. The REST API supports
    both IPv4 and IPv6 address lookup.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.ip2location.io/"):
        """
        :param api_key: IP2Location.io API key
        :param api_url: IP2Location API URL
        """
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, ip: str) -> requests.models.Response:
        """GET request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {
            'ip': ip,
            'format': 'json',
            'key': self.api_key
        }

        response = requests.request("GET", url=self.api_url, headers=headers, params=params)

        return response

    def _api_post(self, ips: List) -> requests.models.Response:
        """POST request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {
            'format': 'json',
            'key': self.api_key
        }

        data = ips

        response = requests.request("POST", url=self.api_url, headers=headers, params=params, data=data)

        return response

    def check_ip(self) -> Union[Dict, str]:
        """Checks IP Geolocation"""
        response = self._api_get(self.ip)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            return response.json()['error']['error_message']

    def bulk_check_ip(self, ips: List) -> Union[Dict, str]:
        """Bulk check (up to 1000) IP addresses geolocation

        [!] This API endpoint requires a Starter, Plus or Security Plan to work. [!]
        """
        response = self._api_post(ips=ips)

        if response.status_code == 200:
            return response.json()
        else:
            return response.json()['error']['error_message']
