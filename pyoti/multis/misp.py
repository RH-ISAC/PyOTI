import json
import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, EmailAddress, FileHash, IPAddress, URL


class MISP(Domain, EmailAddress, FileHash, IPAddress, URL):
    """MISP Threat Intel Platform

    The MISP threat sharing platform is a free and open source software helping
    information sharing of threat intelligence including cyber security
    indicators.
    """
    def __init__(self, api_key: str, api_url: str):
        """
        :param api_key: MISP API key
        :param api_url: MISP base API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        EmailAddress.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_post(self, controller: str, query: Dict, verify_ssl: bool) -> requests.models.Response:
        """POST request to API"""
        headers = {
            "Accept": "application/json",
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request(
            "POST",
            url=f"{self.api_url}/{controller}/restSearch",
            data=json.dumps(query),
            headers=headers,
            verify=verify_ssl
        )

        return response

    def _search_query(self, iocvalue: str, limit: int, warninglist: bool) -> Dict:
        """Sets parameters for search query

        :param iocvalue: IOC value
        :param limit: number of results
        :param warninglist: enforce MISP warninglist
        :return: dict
        """
        query = {"value": iocvalue, "limit": limit, "enforceWarninglist": warninglist}

        return query

    def check_domain(self, controller: str = "events", limit: int = 50, verify_ssl: bool = True, warninglist: bool = True) -> Dict:
        """Checks Domain reputation

        :param controller: the MISP controller to query
        :param limit: number of results
        :param verify_ssl: verify cert
        :param warninglist: enforce MISP warninglist
        :return: dict of lists of MISP events
        """
        query = self._search_query(iocvalue=self.domain, limit=limit, warninglist=warninglist)

        response = self._api_post(controller=controller, query=query, verify_ssl=verify_ssl)

        return response.json()

    def check_email(self, controller: str = "events", limit: int = 50, verify_ssl: bool = True, warninglist: bool = True) -> Dict:
        """Checks Email Address reputation

        :param controller: the MISP controller to query
        :param limit: number of results
        :param verify_ssl: verify cert
        :param warninglist: enforce MISP warninglist
        :return: dict of lists of MISP events
        """
        query = self._search_query(iocvalue=self.email, limit=limit, warninglist=warninglist)

        response = self._api_post(controller=controller, query=query, verify_ssl=verify_ssl)

        return response.json()

    def check_hash(self, controller: str = "events", limit: int = 50, verify_ssl: bool = True, warninglist: bool = True) -> Dict:
        """Checks File Hash reputation

        :param controller: the MISP controller to query
        :param limit: number of results
        :param verify_ssl: verify cert
        :param warninglist: enforce MISP warninglist
        :return: dict of lists of MISP events
        """
        query = self._search_query(iocvalue=self.file_hash, limit=limit, warninglist=warninglist)

        response = self._api_post(controller=controller, query=query, verify_ssl=verify_ssl)

        return response.json()

    def check_ip(self, controller: str = "events", limit: int = 50, verify_ssl: bool = True, warninglist: bool = True) -> Dict:
        """Checks IP reputation

        :param controller: the MISP controller to query
        :param limit: number of results
        :param verify_ssl: verify cert
        :param warninglist: enforce MISP warninglist
        :return: dict of lists of MISP events
        """
        query = self._search_query(iocvalue=self.ip, limit=limit, warninglist=warninglist)

        response = self._api_post(controller=controller, query=query, verify_ssl=verify_ssl)

        return response.json()

    def check_url(self, controller: str = "events", limit: int = 50, verify_ssl: bool = True, warninglist: bool = True) -> Dict:
        """Checks URL reputation

        :param controller: the MISP controller to query
        :param limit: number of results
        :param verify_ssl: verify cert
        :param warninglist: enforce MISP warninglist
        :return: dict of lists of MISP events
        """
        query = self._search_query(iocvalue=self.url, limit=limit, warninglist=warninglist)

        response = self._api_post(controller=controller, query=query, verify_ssl=verify_ssl)

        return response.json()
