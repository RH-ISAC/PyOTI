import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import FileHash


class CIRCLHashLookup(FileHash):
    """CIRCLHashLookup Known Hash Reputation

    CIRCLHashLookup is a public API to lookup hash values against known database of files.
    NSRL RDS database is included as well as many others that are also included.
    """
    def __init__(self, api_url: str = "https://hashlookup.circl.lu/lookup"):
        """
        :param api_url: CIRCLHashLookup base API URL
        """
        FileHash.__init__(self, api_url=api_url)

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API for single hash lookup"""
        headers = {
            "Accept": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("GET", url=url, headers=headers)

        return response

    def check_hash(self) -> Dict:
        """ Checks File Hash reputation

        :return: request response dict
        """
        if len(self.file_hash) == 32:
            url = f"{self.api_url}/md5/{self.file_hash}"
        elif len(self.file_hash) == 40:
            url = f"{self.api_url}/sha1/{self.file_hash}"
        elif len(self.file_hash) == 64:
            url = f"{self.api_url}/sha256/{self.file_hash}"
        else:
            return {}
        response = self._api_get(url=url)

        return response.json()
