import requests
from typing import Dict, List

from pyoti import __version__
from pyoti.classes import URL
from pyoti.exceptions import GSBError


class GoogleSafeBrowsing(URL):
    """GoogleSafeBrowsing URL Blacklist

    Google Safe Browsing is a blacklist service provided by Google that
    provides lists of URLs for web resources that contain malware or phishing
    content.
    """
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    ):
        URL.__init__(self, api_key, api_url)

    def _api_post(self, endpoint: str, platforms: List[str]) -> requests.models.Response:
        """POST request to API

        :param endpoint: API URL
        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        error_code = [400, 403, 429, 500, 503, 504]

        data = {
            "client": {"clientId": "PyOTI", "clientVersion": f"{__version__}"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "THREAT_TYPE_UNSPECIFIED",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": platforms,
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": self.url}],
            },
        }

        headers = {
            "Accept-Encoding": "gzip",
            "Content-type": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request(
            "POST",
            url=endpoint,
            headers=headers,
            json=data,
            params={"key": self.api_key}
        )

        return response



    def check_url(self, platforms: List[str] = ["ANY_PLATFORM"]) -> Dict:
        """Checks URL reputation

        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        response = self._api_post(self.api_url, platforms)

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            raise GSBError(response.json()["error"]["message"])
