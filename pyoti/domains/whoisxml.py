import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain


class WhoisXML(Domain):
    """WhoisXML WHOIS Records

    WhoisXML gathers a variety of domain ownership and registration data points from WHOIS database
    """
    def __init__(self, api_key: str, api_url: str = "https://www.whoisxmlapi.com/whoisserver/WhoisService"):
        """
        :param api_key: WhoisXML API key
        :param api_url: WhoisXML API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self) -> requests.models.Response:
        """Get request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {
            "apiKey": self.api_key,
            "domainName": self.domain,
            "outputFormat": "JSON",
        }

        response = requests.request("GET", url=self.api_url, headers=headers, params=params)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain reputation"""
        response = self._api_get()

        return response.json()
