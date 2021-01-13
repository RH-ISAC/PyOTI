import aiodns
import asyncio
import json
import requests

from pyoti.classes import IPAddress
from pyoti.exceptions import SpamhausZenError
from pyoti.keys import abuseipdb, spamhausintel
from pyoti.utils import time_check_since_epoch


class AbuseIPDB(IPAddress):
    """AbuseIPDB IP Blacklist

    AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers,
    and abusive activity on the internet by providing a central blacklist to report and
    find IP addresses that have been associated with malicious activity.

    :param api_key: AbuseIPDB API key
    :param api_url: AbuseIPDB API URL
    :param max_age: How far back in time (days) to fetch reports. (defaults to 90 days)
    """

    def __init__(self, api_key=abuseipdb, api_url='https://api.abuseipdb.com/api/v2/check', max_age=90):
        self._max_age = max_age
        IPAddress.__init__(self, api_key, api_url)

    @property
    def max_age(self):
        return self._max_age

    @max_age.setter
    def max_age(self, value):
        self._max_age = value

    def _api_get(self, endpoint):
        params = {
            'ipAddress': self.ip,
            'maxAgeInDays': self.max_age
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        response = requests.request("GET", url=endpoint, headers=headers, params=params)

        return response.json()

    def check_ip(self):
        """Checks IP reputation

        The check endpoint (api.abuseipdb.com/api/v2/check) accepts a single IP
        address (v4 or v6). Optionally you may set the max_age parameter to only
        return reports within the last X number of days.
        """

        response = self._api_get(self.api_url)

        return response


class DNSBlockList(IPAddress):
    """SpamhausZen IP Blacklist

    DNSBlockList queries a list of DNS block lists for IP Addresses, and returns the answer address and the block list it hit on.
    """

    RBL = {
        'b.barracudacentral.org',
        'bl.spamcop.net',
        'zen.spamhaus.org'
    }

    def check_ip(self):
        """Checks IP reputation

        Checks reverse DNS lookup query for a given IP and maps return codes to
        appropriate data source.
        """
        result_list = []
        for rbl in self.RBL:
            answer = self._resolve_ip(blocklist=rbl)
            if answer:
                results = {}
                bl = rbl.split(".")[1]
                if answer[0].host in ['127.0.0.2', '127.0.0.3', '127.0.0.9']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-SBL"

                    result_list.append(results)
                elif answer[0].host in ['127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-XBL"

                    result_list.append(results)
                elif answer[0].host in ['127.0.0.10', '127.0.0.11']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-PBL"

                    result_list.append(results)
                elif answer[0].host in ['127.255.255.252', '127.255.255.254', '127.255.255.255']:
                    raise SpamhausZenError("Error in query!")
                else:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-unknown"

                    result_list.append(results)
        return result_list

    def _reverse_ip(self):
        """Prepares IPv4 address for reverse lookup"""

        rev = '.'.join(reversed(str(self.ip).split(".")))

        return rev

    def _resolve_ip(self, blocklist):
        """Performs reverse DNS lookup"""

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            resolver = aiodns.DNSResolver(loop=loop)

            async def query(name, query_type):
                return await resolver.query(name, query_type)

            coro = query(f'{self._reverse_ip()}.{blocklist}', 'A')
            result = loop.run_until_complete(coro)

            return result

        except aiodns.error.DNSError:
            return



class SpamhausIntel(IPAddress):
    """SpamhauzIntel IP Address Metadata

    SpamhausIntel is an API with metadata relating to compromised IP Addresses.
    """

    def __init__(self, api_key=spamhausintel, api_url='https://api.spamhaus.org/api/v1/login'):
        self._token = None
        self._expires = None
        IPAddress.__init__(self, api_key, api_url)

    def _api_login(self):
        data = {
            "username": spamhausintel.split(":")[0],
            "password": spamhausintel.split(":")[1],
            "realm": "intel"
        }

        response = requests.request("POST", url=self.api_url, data=json.dumps(data))

        if response.status_code == 200:
            self._token = response.json()["token"]
            self._expires = response.json()["expires"]
            return response.json()

    def _api_get(self, type, ip, mask):
        if not self._token:
            self._api_login()
        if not time_check_since_epoch(self._expires):
            self._api_login()

        headers = {'Authorization': f'Bearer {self._token}'}

        response = requests.request("GET", url=f'https://api.spamhaus.org/api/intel/v1/byobject/cidr/XBL/listed/{type}/{ip}/{mask}', headers=headers)

        return response

    def check_ip(self):
        get = self._api_get(type="live", ip=self.ip, mask="32")

        if get.status_code == 200:
            return get.json()
