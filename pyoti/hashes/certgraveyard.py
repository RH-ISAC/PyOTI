import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import FileHash


class CertGraveyard(FileHash):
    """CertGraveyard

    The Cert Graveyard is a centralized place to document the abuse of code-signing certificates.
    """
    def __init__(self, api_key: str, api_url: str = "https://certgraveyard.org/api/query_database"):
        FileHash.__init__(self, api_key=api_key, api_url=api_url)

    def _api_post(self, data: Dict) -> requests.models.Response:
        """POST request to CertGraveyard API"""
        headers = {
            "X-API-KEY": self._api_key,
            'Content-Type': 'application/json',
            'User-Agent': f"PyOTI {__version__}"
        }

        response = requests.request("POST", url=self.api_url, json=data, headers=headers)

        return response

    def check_hash(self) -> Dict:
        """Checks FileHash for abused code signing certificate"""
        data = {
            'search_parameter': 'sha256',
            'search_term': self.file_hash
        }

        response = self._api_post(data=data)

        return response.json()
