import json
import subprocess

from domaintools import API

from pyoti.classes import Domain
from pyoti.keys import domaintools
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
