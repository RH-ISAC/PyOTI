import aiodns
import asyncio
import requests

from nslookup import Nslookup

from pyoti.classes import IPAddress
from pyoti.exceptions import SpamhausZenError
from pyoti.keys import abuseipdb


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

    def check_ip(self):
        """Checks IP reputation

        The check endpoint (api.abuseipdb.com/api/v2/check) accepts a single IP
        address (v4 or v6). Optionally you may set the max_age parameter to only
        return reports within the last X number of days.
        """

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
    """SpamhausZen IP Blacklist

    SpamhausZen is the combination of all Spamhaus IP-based DNSBLs into one single
    powerful and comprehensive blocklist to make querying faster and simpler. It
    contains the SBL, SBLCSS, XBL and PBL blocklists.
    """

    def check_ip(self):
        """Checks IP reputation

        Checks reverse DNS lookup query for a given IP and maps return codes to
        appropriate data source.
        """

        answer = self._resolve_ip()
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
        """Prepares IPv4 address for reverse lookup"""

        rev = '.'.join(reversed(str(self.ip).split(".")))

        return rev

    def _ns_resolve_ip(self):
        """Depreciated in favor of aiodns library"""

        dns = Nslookup(dns_servers=["1.1.1.1"])
        domain = f"{self._reverse_ip()}.zen.spamhaus.org"
        a_record = dns.dns_lookup(domain)

        return a_record.answer

    def _resolve_ip(self):
        """Performs reverse DNS lookup"""

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            resolver = aiodns.DNSResolver(loop=loop)

            async def query(name, query_type):
                return await resolver.query(name, query_type)

            coro = query(f'{self._reverse_ip()}.zenspamhaus.org', 'A')
            result = loop.run_until_complete(coro)

            return result

        except aiodns.error.DNSError as e:
            return e
