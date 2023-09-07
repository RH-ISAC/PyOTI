import requests
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import Domain, IPAddress, FileHash, URL


class Triage(Domain, IPAddress, FileHash, URL):
    """
    Triage is Hatching's revolutionary sandboxing solution. It leverages a unique architecture, developed with scaling
    and performance in mind from the start. Triage features Windows, Linux, Android, and macOS analysis capabilities
    and can scale up to 500,000 analyses per day.
    """
    def __init__(self, api_key: str, api_url: str = "https://tria.ge/api/v0"):
        """
        :param api_key: Triage API key
        :param api_url: Triage base API url
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str, params: Optional[Dict]) -> requests.models.Response:
        """GET request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "Authorization": f"Bearer {self.api_key}"
        }
        response = requests.request("GET", url=url, headers=headers, params=params)

        return response

    def check_domain(self) -> Dict:
        """Check if domain was extracted from C2 data"""
        params = {"query": f"domain:{self.domain}"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def check_hash(self) -> Dict:
        """Check if file hash has been seen by Triage"""
        params = {}
        if len(self.file_hash) == 32:
            params["query"] = f"md5:{self.file_hash}"
        elif len(self.file_hash) == 40:
            params["query"] = f"sha1:{self.file_hash}"
        elif len(self.file_hash) == 64:
            params["query"] = f"sha256:{self.file_hash}"
        else:
            return {"error": "You can only search by MD5, SHA1, or SHA256!"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def check_ip(self) -> Dict:
        """Check if IP address was extracted from C2 data"""
        params = {"query": f"ip:{self.ip}"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def check_url(self) -> Dict:
        """Check if URL was extracted from C2 data"""
        params = {"query": f"url:{self.url}"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def get_sample_summary(self, sample_id: str) -> Dict:
        """Get the short summary of a sample and its analysis tasks

        :param sample_id: The sample ID to get summary of
        """
        response = self._api_get(url=f"{self.api_url}/samples/{sample_id}/summary", params=None)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {}

    def get_sample_overview(self, sample_id: str) -> Dict:
        """Get the overview of a sample and its analysis tasks. This contains a one-pager with all the high-level
        information related to the sample including malware configuration, signatures, scoring, etc.

        :param sample_id: The sample ID to get summary overview of
        """
        response = self._api_get(url=f"{self.api_url}/samples/{sample_id}/overview.json", params=None)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {}

    def get_sample(self, sample_id: str) -> Dict:
        """Queries the sample with the specified ID

        :param sample_id: The sample ID to query
        """
        response = self._api_get(url=f"{self.api_url}/samples/{sample_id}", params=None)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {}
