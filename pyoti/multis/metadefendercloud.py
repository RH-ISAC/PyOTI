import requests
from typing import Dict, List
from urllib.parse import quote

from pyoti import __version__
from pyoti.classes import Domain, IPAddress, FileHash, URL


class MetaDefenderCloudV4(Domain, IPAddress, FileHash, URL):
    """
    MetaDefender Cloud is a cloud-based platform that offers multiple technologies to protect against file-based
    attacks, such as Deep Content Disarm and Reconstruction, Multiscanning, Sandbox and Website Scanning. It has a high
    malware detection rate, a large file reputation database and a CVE scanner.
    """

    def __init__(self, api_key: str, api_url: str = "https://api.metadefender.com/v4"):
        """
        :param api_key: MetaDefender Cloud API key
        :param api_url: MetaDefender Cloud base API url
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "apikey": self.api_key
        }
        response = requests.request("GET", url=url, headers=headers)

        return response

    def _api_post(self, url: str, data: Dict, scan_details: bool) -> requests.models.Response:
        """POST request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "apikey": self.api_key,
            "Content-Type": "application/json"
        }
        if scan_details:
            headers["includescandetails"] = "1"
        response = requests.request("POST", url=url, headers=headers, json=data)

        return response

    def get_api_info(self) -> Dict:
        """Retrieve information about your apikey"""
        response = self._api_get(url=f"{self.api_url}/apikey")

        return response.json()

    def check_domain(self) -> Dict:
        """
        Retrieve information about a given fully qualified domain name (FQDN) from a CIF server including but not
        limited to: provider of the FQDN, a security assessment about the FQDN, and time of detection.
        """
        response = self._api_get(url=f"{self.api_url}/domain/{self.domain}")

        return response.json()

    def check_hash(self) -> Dict:
        """Retrieve scan reports by looking up a hash using MD5, SHA1 or SHA256"""
        if len(self.file_hash) == 32 or len(self.file_hash) == 40 or len(self.file_hash) == 64:
            response = self._api_get(url=f"{self.api_url}/hash/{self.file_hash}")

            return response.json()
        else:
            return {"error": "You must provide an MD5, SHA1, or SHA256 file hash"}

    def check_ip(self) -> Dict:
        """Retrieve information about given IP (IPv4 + IPv6) from a CIF server"""
        response = self._api_get(url=f"{self.api_url}/ip/{self.ip}")

        return response.json()

    def check_url(self) -> Dict:
        """Retrieve information about given observable (URL) from a CIF server."""
        response = self._api_get(url=f"{self.api_url}/url/{quote(self.api_url, safe='')}")

        return response.json()

    def bulk_check_domains(self, domains: List[str]) -> Dict:
        """
        Bulk retrieve information about a list of fully qualified domain names (FQDNs) from a CIF server including but
        not limited to: provider of the FQDNs, a security assessment about the FQDNs, and time of detection.
        """
        data = {"fqdn": domains}
        response = self._api_post(url=f"{self.api_url}/domain", data=data, scan_details=False)

        return response.json()

    def bulk_check_hashes(self, hashes: List[str], include_scan_details: bool = False) -> Dict:
        """Look up the scan results based on MD5, SHA1, or SHA256 for multiple data hashes"""
        if len(hashes) <= 1000:
            data = {"hash": hashes}
            response = self._api_post(url=f"{self.api_url}/hash", data=data, scan_details=include_scan_details)

            return response.json()
        else:
            return {"error": "You can only bulk search up to 1000 hashes at a single time!"}

    def bulk_check_ips(self, ips: List[str]) -> Dict:
        """Retrieve information about a list of IP's (Pv4/IPv6)"""
        data = {"address": ips}
        response = self._api_post(url=f"{self.api_url}/ip", data=data, scan_details=False)

        return response.json()

    def bulk_check_urls(self, urls: List[str]) -> Dict:
        """Retrieve information about a list of given observables (URLs) from a CIF server."""
        data = {"url": urls}
        response = self._api_post(url=f"{self.api_url}/url", data=data, scan_details=False)

        return response.json()
