import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, EmailAddress, IPAddress


class WhoisXML(Domain, EmailAddress, IPAddress):
    """WhoisXML WHOIS Records

    WhoisXML gathers a variety of domain ownership and registration data points from WHOIS database
    """
    def __init__(self, api_key: str, api_url: str = "https://www.whoisxmlapi.com/whoisserver/WhoisService"):
        """
        :param api_key: WhoisXML API key
        :param api_url: WhoisXML API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        EmailAddress.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, lookup: str) -> requests.models.Response:
        """Get request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {
            "apiKey": self.api_key,
            "domainName": lookup,
            "outputFormat": "JSON",
            "ip": 1,  # return IPs for the domain name
            "ipWhois": 1,  # return the WHOIS record for the hosting IP if the WHOIS record for the tld of the input domain is not supported
            "checkProxyData": 1,  # fetch proxy/WHOIS guard data in the WhoisRecord → privateWhoisProxy schema element
            "ignoreRawTexts": 1  # strip all raw text from the output
        }

        response = requests.request("GET", url=self.api_url, headers=headers, params=params)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain WHOIS"""
        response = self._api_get(lookup=self.domain)

        return response.json()

    def check_email(self) -> Dict:
        """Checks Domain WHOIS from Email Address"""
        response = self._api_get(lookup=self.email)

        return response.json()

    def check_ip(self) -> Dict:
        """Checks IP WHOIS"""
        response = self._api_get(lookup=self.ip)

        return response.json()

