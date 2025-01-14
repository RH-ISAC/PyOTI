import json
import requests
from typing import Dict, List

from pyoti import __version__
from pyoti.classes import FileHash
from pyoti.exceptions import CIRCLHashLookupError


class CIRCLHashLookup(FileHash):
    """CIRCLHashLookup Known Hash Reputation

    CIRCLHashLookup is a public API to lookup hash values against known database of files.
    NSRL RDS database is included as well as many others that are also included.
    """
    def __init__(self, api_url: str = "https://hashlookup.circl.lu/"):
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

    def _api_post(self, url: str, hash_list: List[str]) -> requests.models.Response:
        """POST request to API for bulk hash lookup"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }

        data = {"hashes": hash_list}

        response = requests.request("POST", url=url, headers=headers, data=json.dumps(data))

        return response

    def check_hash(self) -> Dict:
        """ Checks File Hash reputation

        :return: request response dict
        """
        if len(self.file_hash) == 32:
            url = f"{self.api_url}/lookup/md5/{self.file_hash}"
        elif len(self.file_hash) == 40:
            url = f"{self.api_url}/lookup/sha1/{self.file_hash}"
        elif len(self.file_hash) == 64:
            url = f"{self.api_url}/lookup/sha256/{self.file_hash}"
        else:
            return {}
        response = self._api_get(url=url)

        return response.json()

    def bulk_check_hash(self, algo: str, hash_list: List[str]) -> Dict:
        """Bulk Check File Hash Reputation

        :param algo: Hashing algorithm to bulk check (MD5 or SHA1)
        :param hash_list: List of hashes (MD5 or SHA1)
        :return: request response dict
        """
        if algo.lower() == "md5":
            url = f"{self.api_url}/bulk/md5"
            if [h for h in hash_list if len(h) != 32]:
                raise CIRCLHashLookupError("Hash list must be all MD5 hashes!")
        elif algo.lower() == "sha1":
            url = f"{self.api_url}/bulk/sha1"
            if [h for h in hash_list if len(h) != 40]:
                raise CIRCLHashLookupError("Hash list must be all SHA1 hashes!")
        else:
            return {}
        response = self._api_post(url=url, hash_list=hash_list)

        return response.json()
