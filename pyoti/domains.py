import json
import pypdns
import requests
import subprocess

from domaintools import API

from pyoti.classes import Domain
from pyoti.keys import circlpassive, domaintools, whoisxml
from pyoti.utils import pypkg_exists


class CheckDMARC(Domain):
    """CheckDMARC SPF/DMARC Records

    CheckDMARC validates SPF and DMARC DNS records.
    """

    pypkg = "checkdmarc"

    def check_domain(self):
        """Checks domain reputation

        Checks for any SPF or DMARC records for a given domain.
        """

        pypkg_exists(self.pypkg)
        process = subprocess.Popen(
            [self.pypkg, self.domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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

    def __init__(self, api_key=circlpassive):
        Domain.__init__(self, api_key=api_key)

    def check_domain(self):
        """Checks domain reputation

        Checks CIRCL Passive DNS for historial DNS records for a given domain.
        """

        credentials = self.api_key.split(":")
        pdns = pypdns.PyPDNS(basic_auth=(credentials[0], credentials[1]))
        query = pdns.query(self.domain)

        # still need to verify if this returns a list or dict
        return query


class IrisInvestigate(Domain):
    """IrisInvestigate Domain Risk Score/Historical DNS Records/SSL Profiles

    Iris is a proprietary threat intelligence/investigation platform by Domaintools

    :param api_key: Domaintools API key
    """

    def __init__(self, api_key=domaintools):
        Domain.__init__(self, api_key)

    def check_domain(self):
        """Checks domain reputation"""

        credentials = self.api_key.split(":")
        api = API(credentials[0], credentials[1])
        iris = api.iris_investigate(domains=self.domain)

        return iris.get('response')


class WhoisXML(Domain):
    """WhoisXML WHOIS Records

    WhoisXML gathers a variety of domain ownership and registration data points from WHOIS database

    :param api_key: WhoisXML API key
    :param api_url: WhoisXML API URL
    """

    def __init__(self, api_key=whoisxml, api_url='https://www.whoisxmlapi.com/whoisserver/WhoisService'):
        Domain.__init__(self, api_key=api_key, api_url=api_url)

    def check_domain(self):
        """Checks Domain reputation"""

        params = {
            'apiKey': self.api_key,
            'domainName': self.domain,
            'outputFormat': 'JSON'
        }

        response = requests.request("GET", url=self.api_url, params=params)

        return response.json()
