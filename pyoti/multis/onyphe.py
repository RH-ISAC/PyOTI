import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, IPAddress


class Onyphe(Domain, IPAddress):
    """Onyphe Cyber Defense Search Engine

    ONYPHE is a cyber defense search engine for opensource and threat intelligence
    data collected by crawling various sources available on the internet or by
    listening to internet background noise.
    """
    def __init__(self, api_key: str, api_url: str = "https://www.onyphe.io/api/v2"):
        """
        :param api_key: Onyphe API key
        :param api_url: Onyphe base API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str) -> requests.models.Response:
        """Get request to API

        :param endpoint: Onyphe API endpoint
        :return: dict of request response
        """
        headers = {
            "Authorization": f"apikey {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("GET", url=endpoint, headers=headers)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of request response
        """
        url = f"{self.api_url}/summary/domain/{self.domain}"
        response = self._api_get(url)

        return response.json()

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of request response
        """
        url = f"{self.api_url}/summary/ip/{self.ip}"
        response = self._api_get(url)

        return response.json()
