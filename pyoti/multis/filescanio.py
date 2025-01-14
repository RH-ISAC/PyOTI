import requests
from typing import Dict, List, Optional

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL


class FileScanIO(Domain, FileHash, IPAddress, URL):
    """
    FileScan.IO is a Next-Gen Sandbox and free malware analysis service. Operating at 10x speed compared to traditional
    sandboxes with 90% less resource usage, its unique adaptive threat analysis technology also enables zero-day
    malware detection and more Indicator of Compromise (IOCs) extraction.
    """

    def __init__(self, api_key: str, api_url: str = "https://www.filescan.io"):
        """
        :param api_key: FileScanIO API key
        :param api_url: FileScanIO base API url
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str, params: Optional[Dict]) -> requests.models.Response:
        """GET request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}"
        }
        response = requests.request("GET", url=url, headers=headers, params=params)

        return response

    def _api_post(self, url: str, data: List):
        """POST request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "Content-Type": "application/json"
        }
        response = requests.request("POST", url=url, headers=headers, json=data)

        return response

    def check_domain(self) -> Dict:
        """Get the reputation for one given domain"""
        params = {"ioc_value": self.domain}
        response = self._api_get(url=f"{self.api_url}/api/reputation/domain", params=params)

        return response.json()

    def check_hash(self) -> Dict:
        """Get the reputation for one given hash"""
        if len(self.file_hash) == 64:
            params = {'sha256': self.file_hash}
            response = self._api_get(url=f"{self.api_url}/api/reputation/hash", params=params)

            return response.json()
        else:
            return {"error": "You can only search for SHA256 hashes!"}

    def check_ip(self) -> Dict:
        """Get the reputation for one given IP address"""
        params = {"ioc_value": self.ip}
        response = self._api_get(url=f"{self.api_url}/api/reputation/ip", params=params)

        return response.json()

    def check_url(self) -> Dict:
        """Get the reputation for one given URL"""
        params = {"ioc_value": self.url}
        response = self._api_get(url=f"{self.api_url}/api/reputation/url", params=params)

        return response.json()

    def bulk_check_domains(self, domains: List) -> Dict:
        """Get the reputation for multiple domains"""
        response = self._api_post(url=f"{self.api_url}/api/reputation/domain", data=domains)

        return response.json()

    def bulk_check_hashes(self, hashes: List) -> Dict:
        """Get the reputation for multiple hashes"""
        for h in hashes:
            if len(h) != 64:
                return {"error": "You can only search for SHA256 hashes!"}

        response = self._api_post(url=f"{self.api_url}/api/reputation/hash", data=hashes)

        return response.json()

    def bulk_check_ips(self, ips: List) -> Dict:
        """Get the reputation for multiple IP addresses"""
        response = self._api_post(url=f"{self.api_url}/api/reputation/ip", data=ips)

        return response.json()

    def bulk_check_urls(self, urls: List) -> Dict:
        """Get the reputation for multiple URLs"""
        response = self._api_post(url=f"{self.api_url}/api/reputation/url", data=urls)

        return response.json()
