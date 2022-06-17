import requests
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import PyOTIError, URLhausError


class URLhaus(Domain, FileHash, IPAddress, URL):
    """URLhaus Malware URL Exchange

    URLhaus is a project from abuse.ch with the goal of collecting, tracking,
    and sharing malicious URLs that are being used for malware distribution.
    """
    def __init__(self, api_url: str = "https://urlhaus-api.abuse.ch/v1", url_id: Optional[str] = None):
        """
        :param api_url: URLhaus API URL
        :param url_id: search by URLhaus urlid
        """
        self._url_id = url_id
        Domain.__init__(self, api_url=api_url)
        FileHash.__init__(self, api_url=api_url)
        IPAddress.__init__(self, api_url=api_url)
        URL.__init__(self, api_url=api_url)

    @property
    def url_id(self):
        return self._url_id

    @url_id.setter
    def url_id(self, value):
        self._url_id = value

    def _api_post(self, url: str, data: Dict) -> requests.models.Response:
        """POST request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}

        response = requests.request("POST", url=url, data=data, headers=headers)

        return response

    def _check_host(self, ioc) -> Dict:
        """POST request to /host/ endpoint

        :param ioc: domain, ip address, hostname, filehash, url
        :return: dict of request response
        """
        data = {"host": ioc}
        url = f"{self.api_url}/host/"
        response = self._api_post(url, data)

        return response.json()

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of request response
        """
        return self._check_host(self.domain)

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        :return: dict of request response
        """
        url = f"{self.api_url}/payload/"
        if len(self.file_hash) == 32:
            data = {"md5_hash": self.file_hash}
            response = self._api_post(url, data)
        elif len(self.file_hash) == 64:
            data = {"sha256_hash": self.file_hash}
            response = self._api_post(url, data)
        else:
            raise URLhausError(
                "/payload/ endpoint requires a valid MD5 or SHA-256 hash!"
            )

        return response.json()

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of request response
        """
        return self._check_host(self.ip)

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of request response
        """
        data = {"url": self.url}
        url = f"{self.api_url}/url/"
        response = self._api_post(url, data)

        return response.json()

    def check_urlid(self) -> Dict:
        """Checks ID of a URL tracked by URLhaus

        :return: dict of request response
        """
        data = {"urlid": self.url_id}
        url = f"{self.api_url}/urlid/"
        response = self._api_post(url, data)

        return response.json()
