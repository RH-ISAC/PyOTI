import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import URL


class Phishtank(URL):
    """Phishtank Anti-Phishing

    Phishtank is a collaborative clearing house for data and information about
    phishing on the internet.
    """
    def __init__(self, api_key: str, api_url: str = "https://checkurl.phishtank.com/checkurl/"):
        """
        :param api_key: Phishtank API key
        :param api_url: Phishtank API URL
        """
        URL.__init__(self, api_key, api_url)

    def _api_post(self) -> requests.models.Response:
        """POST request to API"""
        data = {
            "format": "json",
            "url": self.url
        }

        headers = {
            "app_key": self.api_key,
            "User-agent": f"phishtank/PyOTI {__version__}"
        }

        response = requests.request("POST", url=self.api_url, data=data, headers=headers)

        return response

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of request response
        """
        response = self._api_post()
        r = response.json()

        return r.get('results')
