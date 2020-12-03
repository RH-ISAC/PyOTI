import requests

from nslookup import Nslookup

from pyoti.classes import IPAddress
from pyoti.exceptions import SpamhausZenError
from pyoti.keys import abuseipdb


class AbuseIPDB(IPAddress):
    def __init__(self, api_key=abuseipdb, api_url='https://api.abuseipdb.com/api/v2/check', max_age=90):
        self._max_age = max_age
        IPAddress.__init__(self, api_key, api_url)

    @property
    def max_age(self):
        return self._max_age

    @max_age.setter
    def max_age(self, value):
        self._max_age = value

    def check_ip(self):
        query = {
            'ipAddress': self.ip,
            'maxAgeInDays': self.max_age
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        response = requests.request("GET", url=self.api_url, headers=headers, params=query)

        return response.json()


class SpamhausZen(IPAddress):
    def check_ip(self):
        answer = self._lookup_ip()
        if answer:
            results = {}
            if answer[0] in ['127.0.0.2', '127.0.0.3', '127.0.0.9']:
                results["address"] = answer[0]
                results["blocklist"] = "spamhaus-block-list"

                return  results
            elif answer[0] in ['127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7']:
                results["address"] = answer[0]
                results["blocklist"] = "spamhaus-exploits-block-list"

                return results
            elif answer[0] in ['127.255.255.252', '127.255.255.254', '127.255.255.255']:
                raise SpamhausZenError("Error in query!")
            else:
                results["address"] = answer[0]
                results["blocklist"] = "unknown"

                return results

    def _reverse_ip(self):
        rev = '.'.join(reversed(str(self.ip).split(".")))

        return rev

    def _lookup_ip(self):
        dns = Nslookup(dns_servers=["1.1.1.1"])
        domain = f"{self._reverse_ip()}.zen.spamhaus.org"
        a_record = dns.dns_lookup(domain)

        return a_record.answer
