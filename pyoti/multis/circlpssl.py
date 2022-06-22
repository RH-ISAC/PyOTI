import requests
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import FileHash, IPAddress


class CIRCLPSSL(FileHash, IPAddress):
    """CIRCLPSSL Historical X.509 Certificates

    CIRCL Passive SSL stores historical X.509 certificates seen per IP address.
    """
    def __init__(self, api_key: str, api_url: str = "https://www.circl.lu/v2pssl"):
        """
        :param api_key: CIRCLPSSL API key
        :param api_url: CIRCLPSSL base API URL
        """
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API"""
        credentials = self.api_key.split(":")

        headers = {"User-Agent": f"PyOTI {__version__}"}

        response = requests.request("GET", url=url, auth=(credentials[0], credentials[1]), headers=headers)

        return response

    def check_ip(self, cidr_block: Optional[int] = 32) -> Dict:
        """Checks IP reputation

        Checks CIRCL Passive SSL for historical X.509 certificates for a given IP.

        :param cidr_block: can be CIDR blocks between /23 and /32
        :return: dict of query results
        """
        url = f"{self.api_url}/query/{self.ip}/{cidr_block}"
        response = self._api_get(url=url)

        return response.json()

    def check_hash(self) -> Dict:
        """Checks SHA1 fingerprint of a certificate

        Checks CIRCL Passive SSL for historical X.509 certificates for a given
        certificate fingerprint.

        :return: dict of query results
        """
        url = f"{self.api_url}/cquery/{self.file_hash}"
        response = self._api_get(url=url)

        return response.json()

    def fetch_cert(self) -> Dict:
        """Fetch Certificate

        Fetches/parses a specified certificate from CIRCL Passive SSL for a
        given certificate fingerprint.

        :return: dict with certificate info
        """
        url = f"{self.api_url}/cfetch/{self.file_hash}"
        response = self._api_get(url=url)

        return response.json()
