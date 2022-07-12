import aiodns
import asyncio
import pycares
import sys
from typing import Dict, List, Union

from pyoti.classes import Domain, IPAddress


class DNSBlockList(Domain, IPAddress):
    """DNSBlockList Domain/IP Block List

    DNSBlockList queries a list of DNS block lists for Domains or IP Addresses,
    and returns the answer address and the block list it hit on.
    """
    RBL = {  # IP-Based Zones
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "zen.spamhaus.org",
    }

    DBL = {  # Domain-Based Zones
        "dbl.spamhaus.org",
        "multi.uribl.com",
        "multi.surbl.org",
    }

    RBL_CODES = {
        "barracudacentral": {
            "127.0.0.2": "brbl"
        },
        "spamcop": {
            "127.0.0.2": "scbl"
        },
        "spamhaus": {
            "127.0.0.2": "sbl",
            "127.0.0.3": "css",
            "127.0.0.4": "xbl",
            "127.0.0.9": "drop",
            "127.0.0.10": "pbl",
            "127.0.0.11": "pbl",
            "127.255.255.252": "Typing error in DNSBL name!",
            "127.255.255.245": "Query via public/open resolver!",
            "127.255.255.255": "Excessive number of queries!"
        }
    }

    DBL_CODES = {
        "spamhaus": {
            "127.0.1.2": "spam",
            "127.0.1.4": "phish",
            "127.0.1.5": "malware",
            "127.0.1.6": "botnet-c2",
            "127.0.1.102": "abused-legit-spam",
            "127.0.1.103": "abused-spammed-redirector",
            "127.0.1.104": "abused-legit-phish",
            "127.0.1.105": "abused-legit-malware",
            "127.0.1.106": "abused-legit-botnet-c2",
            "127.0.1.255": "IP queries prohibited!",
            "127.255.255.252": "Typing error in DNSBL name!",
            "127.255.255.254": "Anonymous query through public resolver!",
            "127.255.255.255": "Excessive number of queries!"
        },
        "surbl": {
            "127.0.0.1": "Access is blocked!",
            "127.0.0.8": "phish",
            "127.0.0.16": "malware",
            "127.0.0.24": ["phish", "malware"],
            "127.0.0.64": "spam",
            "127.0.0.72": ["phish", "spam"],
            "127.0.0.80": ["malware", "spam"],
            "127.0.0.88": ["phish", "malware", "spam"],
            "127.0.0.128": "abused-legit",
            "127.0.0.136": ["phish", "abused-legit"],
            "127.0.0.144": ["malware", "abused-legit"],
            "127.0.0.152": ["phish", "malware", "abused-legit"],
            "127.0.0.192": ["spam", "abused-legit"],
            "127.0.0.200": ["phish", "spam", "abused-legit"],
            "127.0.0.208": ["malware", "spam", "abused-legit"],
            "127.0.0.216": ["phish", "malware", "spam", "abused-legit"]
        },
        "uribl": {
            "127.0.0.1": "Query is blocked! Possibly due to high volume.",
            "127.0.0.2": "black",
            "127.0.0.4": "grey",
            "127.0.0.8": "red",
            "127.0.0.14": "multi"
        }
    }

    def __init__(self, domain: str = None, ip: str = None):
        Domain.__init__(self, domain=domain)
        IPAddress.__init__(self, ip=ip)

    def check_domain(self) -> List[Dict]:
        """Checks Domain reputation

        Checks DNS lookup query for a given domain and maps return codes to
        appropriate data source.

        :return: list of dict with query response address and blocklist the domain was found on
        """
        result_list = []
        for dbl in self.DBL:
            answer = self._a_query(blocklist=dbl, type="domain")
            if answer:
                results = {}
                bl = dbl.split(".")[1]
                zone = self.DBL_CODES[bl].get(answer[0].host, "unknown")
                results["address"] = answer[0].host
                if answer[0].host in [
                    "127.0.0.1",
                    "127.0.1.255",
                    "127.255.255.252",
                    "127.255.255.254",
                    "127.255.255.255"
                ]:
                    results["error"] = f"{bl}:{zone}"
                else:
                    results["blocklist"] = f"{bl}-{zone}"
                result_list.append(results)
        return result_list

    def check_ip(self) -> List[Dict]:
        """Checks IP reputation

        Checks reverse DNS lookup query for a given IP and maps return codes to
        appropriate data source.

        :return: list of dict with query response address and blocklist the IP was found on
        """
        result_list = []
        for rbl in self.RBL:
            answer = self._a_query(blocklist=rbl, type="ip")
            if answer:
                results = {}
                bl = rbl.split(".")[1]
                zone = self.RBL_CODES[bl].get(answer[0].host, "unknown")
                results["address"] = answer[0].host
                if answer[0].host in [
                    "127.255.255.252",
                    "127.255.255.254",
                    "127.255.255.255"
                ]:
                    results["error"] = f"{bl}:{zone}"
                else:
                    results["blocklist"] = f"{bl}-{zone}"
                result_list.append(results)
        return result_list

    def _reverse_ip(self, ipaddr: str) -> str:
        """Prepares IPv4 address for reverse lookup

        :param ipaddr: IP Address
        :return: reversed IP address for DNS query
        """
        return ".".join(reversed(ipaddr.split(".")))

    def _a_query(self, blocklist: str, type: str) -> Union[List[pycares.ares_query_a_result], None]:
        """DNS A record query

         :param blocklist: DNS blocklist URL
         :param type: ip or domain
         :return: list of ares_query_a_result
         """
        try:
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            async def query_a(name):
                resolver = aiodns.DNSResolver(nameservers=["208.67.222.222"])  # OpenDNS nameserver
                return await resolver.query(name, "A")

            if type == "ip":
                host = f"{self._reverse_ip(ipaddr=self.ip)}.{blocklist}"
            elif type == "domain":
                host = f"{self.domain}.{blocklist}"

            result = asyncio.run(query_a(name=host))

            return result

        except aiodns.error.DNSError:
            return
