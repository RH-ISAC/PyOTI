import json
import pypdns
import requests
import subprocess

from domaintools import API
from typing import Dict, List

from pyoti.classes import Domain
from pyoti.utils import pypkg_exists


class CheckDMARC(Domain):
    """CheckDMARC SPF/DMARC Records

    CheckDMARC validates SPF and DMARC DNS records.
    """
    pypkg: str = "checkdmarc"

    def check_domain(self) -> Dict:
        """Checks domain reputation

        Checks for any SPF or DMARC records for a given domain.

        :return: dict
        """
        pypkg_exists(self.pypkg)
        process = subprocess.Popen(
            [self.pypkg, self.domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        process.wait()
        stdout, stderr = process.communicate()

        dmarc_info = stdout.decode("utf-8"), stderr
        dmarc_str = dmarc_info[0]
        dmarc_json = json.loads(dmarc_str)

        return dmarc_json


class CIRCLPDNS(Domain):
    """CIRCLPDNS Historcal DNS Records

    CIRCL Passive DNS stores historical DNS records from various resources including malware analysis or partners.
    """
    def __init__(self, api_key: str):
        """
        :param api_key: CIRCL PassiveDNS API key
        """
        Domain.__init__(self, api_key=api_key)

    def _api(self) -> pypdns.PyPDNS:
        """Instantiates PyPDNS API

        :return: CIRCL Passive DNS client
        """
        credentials = self.api_key.split(":")
        pdns = pypdns.PyPDNS(basic_auth=(credentials[0], credentials[1]))

        return pdns

    def check_domain(self) -> List[Dict]:
        """Checks domain reputation

        Checks CIRCL Passive DNS for historial DNS records for a given domain.

        :return: list of dicts
        """
        pdns = self._api()
        query = pdns.query(self.domain)

        return query


class IrisInvestigate(Domain):
    """IrisInvestigate Domain Risk Score/Historical DNS Records/SSL Profiles

    Iris is a proprietary threat intelligence/investigation platform by Domaintools
    """
    def __init__(self, api_key: str):
        """
        :param api_key: Domaintools API key
        """
        Domain.__init__(self, api_key)

    def _api(self) -> domaintools.API:
        """Instantiates Domaintools API

        :return: Domaintools API client
        """
        credentials = self.api_key.split(":")
        api = API(credentials[0], credentials[1])

        return api

    def check_domain(self) -> List[Dict]:
        """Checks domain reputation

        :return: list of dicts
        """
        api = self._api()
        iris = api.iris_investigate(domains=self.domain)

        return iris.get("results")


class WhoisXML(Domain):
    """WhoisXML WHOIS Records

    WhoisXML gathers a variety of domain ownership and registration data points from WHOIS database
    """
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://www.whoisxmlapi.com/whoisserver/WhoisService",
    ):
        """
        :param api_key: WhoisXML API key
        :param api_url: WhoisXML API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str) -> Dict:
        """Get request to API

        :return: dict of request response
        """
        params = {
            "apiKey": self.api_key,
            "domainName": self.domain,
            "outputFormat": "JSON",
        }

        response = requests.request("GET", url=endpoint, params=params)

        return response.json()

    def check_domain(self) -> Dict:
        """Checks Domain reputation"""
        response = self._api_get(self.api_url)

        return response
