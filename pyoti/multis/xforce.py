import base64
import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL


class XForceExchange(Domain, FileHash, IPAddress, URL):
    """XForceExchange

    IBM X-Force Exchange is a cloud-based threat intelligence platform that allows you to consume, share and act on
    threat intelligence. It enables you to rapidly research the latest global security threats, aggregate actionable
    intelligence, consult with experts and collaborate with peers. IBM X-Force Exchange, supported by human- and
    machine-generated intelligence, leverages the scale of IBM X-Force to help users stay ahead of emerging threats.
    """
    def __init__(self, api_key: str, api_url: str = "https://api.xforce.ibmcloud.com/api"):
        enc_bytes = base64.b64encode(api_key.encode("utf-8"))
        api_key = str(enc_bytes, "utf-8")
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url) -> requests.models.Response:
        """GET request to XForce API"""
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {self.api_key}",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("GET", url=url, headers=headers)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain reputation"""
        response = self._api_get(url=f"{self.api_url}/url/{self.domain}")

        return response.json()

    def check_hash(self) -> Dict:
        """Checks File Hash reputation"""
        response = self._api_get(url=f"{self.api_url}/malware/{self.file_hash}")

        return response.json()

    def check_ip(self) -> Dict:
        """Checks IP Address reputation"""
        response = self._api_get(url=f"{self.api_url}/ipr/{self.ip}")

        return response.json()

    def check_url(self) -> Dict:
        """Checks URL reputation"""
        response = self._api_get(url=f"{self.api_url}/url/{self.url}")

        return response.json()
