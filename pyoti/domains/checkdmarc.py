import aiodns
import asyncio
import pycares
import re
import sys
from typing import Dict, List

from pyoti.classes import Domain


class CheckDMARC(Domain):
    """CheckDMARC SPF/DMARC Records

    CheckDMARC validates SPF and DMARC DNS records.
    """
    def __init__(self, domain: str = None):
        Domain.__init__(self, domain=domain)

    def query_txt(self, name: str) -> List[pycares.ares_query_txt_result]:
        """Asynchronous DNS query for TXT record"""
        try:
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            async def query(host, record):
                resolver = aiodns.DNSResolver(nameservers=["208.67.222.222"])  # OpenDNS nameserver
                return await resolver.query(host, record)

            result = asyncio.run(query(host=name, record="TXT"))

            return result
        except aiodns.error.DNSError:
            return []

    def _get_spf(self) -> Dict:
        """Get SPF record for a given Domain"""
        result = self.query_txt(name=self.domain)

        spf_json = {}
        for r in result:
            if re.search(r"^v=spf1", r.text):
                spf_json["txt"] = r.text
                spf_json["ttl"] = r.ttl

        return spf_json

    def _get_dmarc(self) -> Dict:
        """GET DMARC record for a given Domain"""
        result = self.query_txt(name=f"_dmarc.{self.domain}")

        dmarc_json = {}

        try:
            if re.search(r"^v=DMARC", result[0].text):
                dmarc_json["txt"] = result[0].text
                dmarc_json["ttl"] = result[0].ttl

                return dmarc_json

        except IndexError:
            return {}

    def _spoofable_check(self, results: Dict) -> Dict:
        """Check if domain is spoofable"""
        if not results.get("dmarc") or not results.get("spf"):
            results['spoofable'] = True
        elif not re.search(r"([-~]+(all))$", results.get("spf").get("txt")):
            results['spoofable'] = True
        elif re.search(r"\s*p=none;", results.get("dmarc").get("txt")):
            results['spoofable'] = True
        elif not re.search(r"\s*p=([^;]*)\s*", results.get("dmarc").get("txt")):
            results['spoofable'] = True

        return results

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        Checks for any SPF or DMARC records for a given Domain.

        :return: dict
        """
        spf = self._get_spf()
        dmarc = self._get_dmarc()

        results = {"domain": self.domain, "dmarc": dmarc, "spf": spf, 'spoofable': False}

        spoofable_results = self._spoofable_check(results)

        return spoofable_results
