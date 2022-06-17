import requests
from typing import Dict
from urllib.parse import urlencode

from pyoti import __version__
from pyoti.classes import URL
from pyoti.exceptions import LinkPreviewError


class LinkPreview(URL):
    """LinkPreview Shortened URL Previewer

    LinkPreview API provides basic website information from any given URL.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.linkpreview.net"):
        URL.__init__(self, api_key, api_url)

    def _api_get(self) -> requests.models.Response:
        """GET request to API"""
        error_code = [400, 401, 403, 404, 423, 425, 426, 429]

        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {"key": self.api_key, "q": self.url}

        encoded = urlencode(params)

        response = requests.request("GET", url=self.api_url, headers=headers, params=encoded)

        if response.status_code == 200:
            return response

        elif response.status_code in error_code:
            raise LinkPreviewError(response.json()["description"])

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of request response
        """
        response = self._api_get()

        return response.json()
