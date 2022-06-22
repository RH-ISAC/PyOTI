import requests
from typing import Dict, List

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL


OTX_IOC_SECTIONS = {
    "domain": ["general", "geo", "malware", "url_list", "passive_dns"],
    "file_hash": ["general", "analysis"],
    "ip": ["general", "reputation", "geo", "malware", "url_list", "passive_dns"],
    "url": ["general", "url_list"]
}


class OTX(Domain, FileHash, IPAddress, URL):
    """OTX Open Threat Exchange

    AlienVault OTX is a threat data platform that allows security researchers
    and threat data producers to share research and investigate new threats.
    """
    def __init__(self, api_key: str, api_url: str = "https://otx.alienvault.com/api/v1"):
        """
        :param api_key: OTX API key
        :param api_url: OTX base API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str, ioctype: str, iocvalue: str, otx_sections: List) -> Dict:
        """GET request to API

        :param endpoint: OTX API endpoint
        :param ioctype: type of IOC to check
        :param iocvalue: IOC value to check
        :param otx_sections: List of different OTX sections to perform lookup
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"PyOTI {__version__}",
            "X-OTX-API-KEY": self.api_key
        }

        indicator_dict = {}

        for section in otx_sections:

            response = requests.request(
                "GET",
                url=f"{self.api_url}/{endpoint}/{ioctype}/{iocvalue}/{section}",
                headers=headers
            )

            indicator_dict[section] = response.json()

        return indicator_dict

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of query result
        """
        response = self._api_get(
            endpoint="indicators",
            ioctype="domain",
            iocvalue=self.domain,
            otx_sections=OTX_IOC_SECTIONS.get("domain")
        )

        return response

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        :return: dict of query results
        """
        response = self._api_get(
            endpoint="indicators",
            ioctype="file",
            iocvalue=self.file_hash,
            otx_sections=OTX_IOC_SECTIONS.get("file_hash")
        )

        return response

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of query results
        """
        response = self._api_get(
            endpoint="indicators",
            ioctype="IPv4",
            iocvalue=self.ip,
            otx_sections=OTX_IOC_SECTIONS.get("ip")
        )

        return response

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of query results
        """
        response = self._api_get(
            endpoint="indicators",
            ioctype="url",
            iocvalue=self.url,
            otx_sections=OTX_IOC_SECTIONS.get("url")
        )

        return response
