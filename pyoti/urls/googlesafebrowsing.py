import requests
from typing import Dict, List

from pyoti import __version__
from pyoti.classes import URL


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

    def _api_post(self, endpoint: str, platforms: List[str], **kwargs) -> requests.models.Response:
        """POST request to API

        :param endpoint: API URL
        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        if kwargs.get('url_list'):
            threat_entries = []
            for url in kwargs.get('url_list'):
                threat_entries.append({"url": url})
        else:
            threat_entries = [{"url": self.url}]

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
                "threatEntries": threat_entries,
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
        error_code = [400, 403, 429, 500, 503, 504]

        response = self._api_post(self.api_url, platforms)

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            r = {'error': response.json()["error"]["message"]}
            return r

    def bulk_check_url(self, url_list: List[str], platforms: List[str] = ["ANY_PLATFORM"]) -> Dict:
        """Bulk check URL reputation

        :param url_list: List or URLs to check reputation
        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        error_code = [400, 403, 429, 500, 503, 504]

        response = self._api_post(self.api_url, platforms, url_list=url_list)

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            r = {'error': response.json()["error"]["message"]}
            return r