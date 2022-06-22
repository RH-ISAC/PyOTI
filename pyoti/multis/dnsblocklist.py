import aiodns
import asyncio
import pycares
import sys
from typing import Dict, List, Union

from pyoti.classes import Domain, IPAddress
from pyoti.exceptions import SpamhausError


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
                if answer[0].host in ["127.0.1.2"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-spam"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.4"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-phish"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.5"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-malware"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.6"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-botnet-c2"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.102"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-legit"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.103"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-redirector"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.104"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-phish"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.105"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-malware"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.106"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-botnet-c2"

                    result_list.append(results)
                elif answer[0].host in ["127.0.1.255"]:
                    raise SpamhausError("IP queries prohibited!")
                elif answer[0].host in [
                    "127.255.255.252",
                    "127.255.255.254",
                    "127.255.255.255",
                ]:
                    raise SpamhausError("Error in query!")

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
                if answer[0].host in ["127.0.0.2", "127.0.0.3", "127.0.0.9"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-SBL"

                    result_list.append(results)
                elif answer[0].host in [
                    "127.0.0.4",
                    "127.0.0.5",
                    "127.0.0.6",
                    "127.0.0.7",
                ]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-XBL"

                    result_list.append(results)
                elif answer[0].host in ["127.0.0.10", "127.0.0.11"]:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-PBL"

                    result_list.append(results)
                elif answer[0].host in [
                    "127.255.255.252",
                    "127.255.255.254",
                    "127.255.255.255",
                ]:
                    raise SpamhausError("Error in query!")
                else:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-unknown"

                    result_list.append(results)
        return result_list

    def _reverse_ip(self, ipaddr: str) -> str:
        """Prepares IPv4 address for reverse lookup

        :param ipaddr: IP Address
        :return: reversed IP address for DNS query
        """
        rev = ".".join(reversed(str(ipaddr).split(".")))

        return rev

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
                resolver = aiodns.DNSResolver(nameservers=["208.67.222.222"]) #OpenDNS nameserver
                return await resolver.query(name, "A")

            if type == "ip":
                host = f"{self._reverse_ip(ipaddr=self.ip)}.{blocklist}"
            elif type == "domain":
                host = f"{self.domain}.{blocklist}"

            result = asyncio.run(query_a(name=host))

            return result

        except aiodns.error.DNSError:
            return
