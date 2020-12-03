import json
import requests
import subprocess

from domaintools import API

from pyoti.classes import Domain
from pyoti.keys import domaintools, whoisxml
from pyoti.utils import pypkg_exists


class CheckDMARC(Domain):
    pypkg = "checkdmarc"

    def check_domain(self):
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


class IrisInvestigate(Domain):
    def check_domain(self):
        credentials = self._api_key.split(":")
        api = API(credentials[0], credentials[1])
        iris = api.iris_investigate(domains=self.domain)

        return iris.get('response')


class WhoisXML(Domain):
    def __init__(self, api_url='https://www.whoisxmlapi.com/whoisserver/WhoisService'):
        Domain.__init__(self, api_url=api_url)

    def check_domain(self):
        params = {
            'apiKey': whoisxml,
            'domainName': self.domain,
            'outputFormat': 'JSON'
        }

        response = requests.request("GET", url=self.api_url, params=params)

        return response.json()
