import requests
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL


class JoeSandbox(Domain, FileHash, IPAddress, URL):
    """
    Joe Sandbox is a platform that allows you to analyze malware and phishing in depth on various platforms and
    environments. It uses advanced technologies such as hybrid analysis, emulation, machine learning and AI to detect
    and report threats.
    """

    def __init__(self, api_key: str, api_url: str = "https://www.joesandbox.com/api"):
        """
        :param api_key:
        :param api_url:
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_post(self, url: str, params: Optional[Dict] = None) -> requests.models.Response:
        """POST request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}"
        }
        if params:
            params['apikey'] = self.api_key
        else:
            params = {'apikey': self.api_key}

        response = requests.request("POST", url=url, headers=headers, data=params)

        return response

    def server_online(self) -> bool:
        """Check if the Joe Sandbox analysis back end is online or in maintenance mode."""
        response = self._api_post(url=f"{self.api_url}/v2/server/online")

        return response.json()['data']['online']

    def server_info(self) -> Dict:
        """Query information about the server."""
        response = self._api_post(url=f"{self.api_url}/v2/server/info")

        return response.json()

    def account_info(self) -> Dict:
        """Query information about your account."""
        response = self._api_post(url=f"{self.api_url}/v2/account/info")

        return response.json()

    def check_domain(self, ioc: bool = False) -> Dict:
        """
        Check a domain against all sandbox analyses.
        :param ioc: Search domain against all URLs submitted for analysis (False) or search domains contacted during anlysis (True)
        """
        if ioc:
            params = {'ioc-domain': self.domain}
        else:
            params = {'url': self.domain}

        response = self._api_post(url=f"{self.api_url}/v2/analysis/search", params=params)

        return response.json()

    def check_hash(self) -> Dict:
        """Check a file hash against all sandbox analyses"""
        params = {}
        if len(self.file_hash) == 32:
            params['md5'] = self.file_hash
        elif len(self.file_hash) == 40:
            params['sha1'] = self.file_hash
        elif len(self.file_hash) == 64:
            params['sha256'] = self.file_hash
        else:
            return {'error': 'You must provide either an MD5, SHA1, or SHA256 hash to query!'}

        response = self._api_post(url=f"{self.api_url}/v2/analysis/search", params=params)

        return response.json()

    def check_ip(self) -> Dict:
        """Check an IP address against all sandbox analyses"""
        params = {'ioc-public-ip': self.ip}

        response = self._api_post(url=f"{self.api_url}/v2/analysis/search", params=params)

        return response.json()

    def check_url(self, ioc: bool = False) -> Dict:
        """
        Check a URL against all sandbox analyses
        :param ioc: Search URLs submitted for analysis (False) or search URLs contacted during analysis (True)
        """
        if ioc:
            params = {'ioc-url': self.url}
        else:
            params = {'url': self.url}

        response = self._api_post(url=f"{self.api_url}/v2/analysis/search", params=params)

        return response.json()
