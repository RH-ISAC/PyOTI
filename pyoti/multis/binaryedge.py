import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, EmailAddress, IPAddress


class BinaryEdge(Domain, EmailAddress, IPAddress):
    """BinaryEdge continuously collects and correlates data from internet accessible devices, allowing organizations
    to see what is their attack surface and what they are exposing to attackers."""
    def __init__(self, api_key: str, api_url: str = "https://api.binaryedge.io/v2"):
        """
        :param api_key: BinaryEdge API key
        :param api_url: BinaryEdge base API url
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        EmailAddress.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str) -> requests.models.Response:
        """Get request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "X-Key": self.api_key
        }
        response = requests.request("GET", url=url, headers=headers)

        return response

    def check_email_dataleaks(self) -> Dict:
        """Check email address in dataleaks"""
        url = f"{self.api_url}/query/dataleaks/email/{self.email}"
        response = self._api_get(url=url)

        return response.json()

    def check_ip_cve(self) -> Dict:
        """Get list of CVEs that might affect IP"""
        url = f"{self.api_url}/query/cve/ip/{self.ip}"
        response = self._api_get(url=url)

        return response.json()

    def check_ip_host(self) -> Dict:
        """Check IP host reputation

        :return: dict of query results
        """
        url = f"{self.api_url}/query/ip/{self.ip}"
        response = self._api_get(url=url)

        return response.json()

    def get_domain_subdomains(self) -> Dict:
        """Get list of subdomains known from a domain"""
        url = f"{self.api_url}/query/domains/subdomain/{self.domain}"
        response = self._api_get(url=url)

        return response.json()
