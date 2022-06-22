import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, IPAddress


class Pulsedive(Domain, IPAddress):
    """Pulsedive Threat Intelligence Made Easy

    Pulsedive is a free threat intelligence platform. Search, scan, and enrich IPs, URLs, domains and other IOCs from OSINT feeds or submit your own.
    """
    def __init__(self, api_key: str, api_url: str = "https://pulsedive.com/api"):
        """
        :param api_key: Pulsedive API key
        :param api_url: Pulsedive API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str, iocvalue: str) -> requests.models.Response:
        """GET request to API

        :param endpoint: Pulsedive API endpoint for query
        :param iocvalue: domain or ip
        """
        headers = {"User-Agent": f"PyOTI {__version__}"}
        params = {"indicator": iocvalue, "key": self.api_key}

        response = requests.request("GET", url=f"{self.api_url}{endpoint}", headers=headers, params=params)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of request response
        """
        response = self._api_get(endpoint="/info.php", iocvalue=self.domain)

        return response.json()

    def check_ip(self) -> Dict:
        """Checks IP Address reputation

        :return: dict of request response
        """
        response = self._api_get(endpoint="/info.php", iocvalue=self.ip)

        return response.json()
