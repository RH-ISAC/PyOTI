import hashlib
import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import MaltiverseIOCError


class MaltiverseIOC(Domain, FileHash, IPAddress, URL):
    """MaltiverseIOC IOC Search Engine

    Maltiverse is an open IOC search engine providing collective intelligence.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.maltiverse.com"):
        """
        :param api_key: Maltiverse API key
        :param api_url: Maltiverse base API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str) -> requests.models.Response:
        """GET request to API

        :param endpoint: API endpoint
        """
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("GET", url=f"{self.api_url}/{endpoint}", headers=headers)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of query result
        """
        response = self._api_get(endpoint=f"hostname/{self.domain}")

        return response.json()

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        :return: dict of query result
        """
        if len(self.file_hash) == 32:
            response = self._api_get(endpoint=f"search?query=md5:{self.file_hash}")
        elif len(self.file_hash) == 64:
            response = self._api_get(endpoint=f"sample/{self.file_hash}")
        else:
            raise MaltiverseIOCError("You can only query Maltiverse for MD5 or SHA256!")

        return response.json()

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of query result
        """
        response = self._api_get(endpoint=f"ip/{self.ip}")

        return response.json()

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of query result
        """
        url_hash = hashlib.sha256(self.url.encode("utf-8")).hexdigest()
        response = self._api_get(endpoint=f"url/{url_hash}")

        return response.json()
