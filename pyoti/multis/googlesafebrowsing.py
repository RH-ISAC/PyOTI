import requests
from base64 import b64encode
from typing import Dict, List

from pyoti import __version__
from pyoti.classes import Domain, FileHash, URL


class GoogleSafeBrowsing(Domain, FileHash, URL):
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
        Domain.__init__(self, api_key, api_url)
        FileHash.__init__(self, api_key, api_url)
        URL.__init__(self, api_key, api_url)

    def _api_post(
            self, endpoint: str, platforms: str, threat_entry: str, **kwargs
    ) -> requests.models.Response:
        """POST request to API

        :param endpoint: API URL
        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :param threat_entries: digest or url. For more information please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatEntry
        :return: dict of request response
        """
        if threat_entry == 'url':
            entry_type = 'URL'
            if kwargs.get('url_list'):
                entry = []
                for url in kwargs.get('url_list'):
                    entry.append({"url": url})
            else:
                entry = [{"url": self.url}]

        elif threat_entry == 'digest':
            entry_type = 'EXECUTABLE'
            if kwargs.get('hash_list'):
                entry = []
                for h in kwargs.get('hash_list'):
                    encoded_hash = b64encode(bytes.fromhex(h)).decode("utf-8")
                    entry.append({"digest": encoded_hash})
            else:
                encoded_hash = b64encode(bytes.fromhex(self.file_hash)).decode("utf-8")
                entry = [{"digest": encoded_hash}]


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
                "platformTypes": [platforms],
                "threatEntryTypes": [entry_type],
                "threatEntries": entry,
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

    def check_hash(self, platforms: str = "ANY_PLATFORM") -> Dict:
        """Checks FileHash reputation

        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        error_code = [400, 403, 429, 500, 503, 504]

        response = self._api_post(self.api_url, platforms, "digest")

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            r = {'error': response.json()["error"]["message"]}
            return r

    def bulk_check_hashes(self, hash_list: List[str], platforms: str = "ANY_PLATFORM") -> Dict:
        """Bulk check FileHash reputation

        :param hash_list: List of SHA256 hashes to check reputation
        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        error_code = [400, 403, 429, 500, 503, 504]

        response = self._api_post(self.api_url, platforms, "digest", hash_list=hash_list)

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            r = {'error': response.json()["error"]["message"]}
            return r

    def check_url(self, platforms: str = "ANY_PLATFORM") -> Dict:
        """Checks URL reputation

        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        error_code = [400, 403, 429, 500, 503, 504]

        response = self._api_post(self.api_url, platforms, "url")

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            r = {'error': response.json()["error"]["message"]}
            return r

    def bulk_check_url(self, url_list: List[str], platforms: str = "ANY_PLATFORM") -> Dict:
        """Bulk check URL reputation

        :param url_list: List of URLs to check reputation
        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        :return: dict of request response
        """
        error_code = [400, 403, 429, 500, 503, 504]

        response = self._api_post(self.api_url, platforms, "url", url_list=url_list)

        if response.status_code == 200:
            if response.json() == {}:
                r = {'matches': []}
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            r = {'error': response.json()["error"]["message"]}
            return r