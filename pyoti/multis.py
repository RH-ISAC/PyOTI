import aiodns
import asyncio
import base64
import sys

import maltiverse
import pycares
import pymisp
import pypssl
import requests
import time

from maltiverse import Maltiverse
from OTXv2 import OTXv2, IndicatorTypes
from pymisp import ExpandedPyMISP
from typing import Dict, List
from uuid import UUID

from pyoti.classes import Domain, EmailAddress, FileHash, IPAddress, URL
from pyoti.exceptions import (
    MaltiverseIOCError,
    OTXError,
    PyOTIError,
    SpamhausError,
    URLhausHashError,
    VirusTotalError,
)
from pyoti.utils import get_hash_type


class CIRCLPSSL(FileHash, IPAddress):
    """CIRCLPSSL Historical X.509 Certificates

    CIRCL Passive SSL stores historical X.509 certificates seen per IP address.
    """
    def __init__(self, api_key: str):
        """
        :param api_key: CIRCL PassiveSSL API Key
        """
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)

    def _api(self) -> pypssl.PyPSSL:
        """Instantiates PyPSSL API"""
        credentials = self.api_key.split(":")
        pssl = pypssl.PyPSSL(basic_auth=(credentials[0], credentials[1]))

        return pssl

    def check_ip(self) -> Dict:
        """Checks IP reputation

        Checks CIRCL Passive SSL for historical X.509 certificates for a given IP.

        :return: dict of query results
        """
        pssl = self._api()
        query = pssl.query(self.ip)

        return query

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        Checks CIRCL Passive SSL for historical X.509 certificates for a given
        certificate fingerprint.

        :return: dict of query results
        """
        pssl = self._api()
        cquery = pssl.query_cert(self.file_hash)

        return cquery

    def fetch_cert(self) -> Dict:
        """Fetch Certificate

        Fetches/parses a specified certificate from CIRCL Passive SSL for a
        given certificate fingerprint.

        :return: dict with certificate info
        """
        pssl = self._api()
        try:
            cfetch = pssl.fetch_cert(self.file_hash)
        except Exception as e:
            raise PyOTIError(e)

        return cfetch


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

    def _resolve(self, blocklist: str, type: str) -> List[pycares.ares_query_a_result]:
        """DEPRECIATED - USE _a_query()

        Performs DNS lookup

        :param blocklist: DNS blocklist URL
        :parm type: ip or domain
        :return: list of ares_query_a_result
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            resolver = aiodns.DNSResolver(loop=loop, nameservers=["208.67.222.222"])

            async def query(name, query_type):
                return await resolver.query(name, query_type)

            if type == "ip":
                coro = query(f"{self._reverse_ip(ipaddr=self.ip)}.{blocklist}", "A")
            elif type == "domain":
                coro = query(f"{self.domain}.{blocklist}", "A")

            result = loop.run_until_complete(coro)

            return result

        except aiodns.error.DNSError:
            return

    def _a_query(self, blocklist: str, type: str) -> List[pycares.ares_query_a_result]:
        """DNS A record query

         :param blocklist: DNS blocklist URL
         :param type: ip or domain
         :return: list of ares_query_a_result
         """
        try:
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            async def query_a(name):
                resolver = aiodns.DNSResolver(nameservers=["208.67.222.222"])
                return await resolver.query(name, "A")

            if type == "ip":
                host = f"{self._reverse_ip(ipaddr=self.ip)}.{blocklist}"
            elif type == "domain":
                host = f"{self.domain}.{blocklist}"

            result = asyncio.run(query_a(name=host))

            return result

        except aiodns.error.DNSError:
            return

class HybridAnalysis(FileHash, URL):
    """HybridAnalysis Malware Analysis

    HybridAnalysis is a free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology.
    """
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://www.hybrid-analysis.com/api/v2/",
        job_id: str = None,
    ):
        """
        :param api_key: HybridAnalysis API key
        :param api_url: HybridAnalysis API URL
        :param job_id: HybridAnalysis ID for report
        """
        self._job_id = job_id
        FileHash.__init__(self, api_url=api_url, api_key=api_key)
        URL.__init__(self, api_url=api_url, api_key=api_key)

    @property
    def job_id(self):
        return self._job_id

    @job_id.setter
    def job_id(self, value):
        self._job_id = value

    def _api_post(self, endpoint: str, ioctype: str, iocvalue: str) -> Dict:
        """POST request to API

        :param endpoint: HybridAnalysis API endpoint
        :param ioctype: domain, ip, hash, url
        :return: dict of request response
        """
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PyOTI 0.2",
            "api-key": self.api_key,
        }

        data = {ioctype: iocvalue}

        uri = self.api_url + endpoint
        response = requests.request("POST", url=uri, headers=headers, data=data)

        return response.json()

    def _api_get(self, endpoint: str) -> List[Dict]:
        """GET request to API

        :param endpoint: HybridAnalysis API endpoint
        :return: list of dicts in request response
        """
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": "PyOTI 0.2",
            "api-key": self.api_key,
        }

        uri = self.api_url + endpoint
        response = requests.request("GET", url=uri, headers=headers)

        return response.json()

    def check_hash(self) -> List[Dict]:
        """Checks File Hash reputation

        :return: list of dicts in request response
        """
        response = self._api_post(
            endpoint="search/hash", ioctype="hash", iocvalue=self.file_hash
        )
        self.job_id = response[0]["job_id"]
        return response

    def check_url(self) -> List[Dict]:
        """Checks URL reputation

        :return: list of dicts in request response
        """
        response = self._api_post(
            endpoint="search/terms", ioctype="url", iocvalue=self.url
        )["result"]
        try:
            self.job_id = response[0]["job_id"]
            return response
        except IndexError:
            # this exception indicates no results found!
            return

    def check_report(self, sandbox_report: str = "summary") -> Dict:
        """Checks for summary of a submission

        :param sandbox_report: default summary (see https://www.hybrid-analysis.com/docs/api/v2/)
        :return: dict of request response
        """
        return self._api_get(endpoint=f"report/{self.job_id}/{sandbox_report}")


class MaltiverseIOC(Domain, FileHash, IPAddress, URL):
    """MaltiverseIOC IOC Search Engine

    Maltiverse is an open IOC search engine providing collective intelligence.
    """
    def __init__(self, api_key: str):
        """
        :param api_key: Maltiverse API key
        """
        Domain.__init__(self, api_key=api_key)
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)
        URL.__init__(self, api_key=api_key)

    def _api(self, auth_token: str) -> maltiverse.Maltiverse:
        """Instantiates Maltiverse API

        :param auth_token: Maltiverse API key
        :return: Maltiverse API client
        """
        api = Maltiverse(auth_token=auth_token)
        return api

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of query result
        """
        if self.domain:
            api = self._api(self.api_key)
            result = api.hostname_get(self.domain)

            return result
        else:
            raise MaltiverseIOCError("/hostname/ endpoint requires a valid domain!")

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        :return: dict of query result
        """
        api = self._api(self.api_key)
        if get_hash_type(self.file_hash) == "MD5":
            result = api.sample_get_by_md5(self.file_hash)

            return result
        elif get_hash_type(self.file_hash) == "SHA-256":
            result = api.sample_get(self.file_hash)

            return result
        else:
            raise MaltiverseIOCError(
                "/sample/ endpoint requires a valid MD5 or SHA256 hash!"
            )

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of query result
        """
        if self.ip:
            api = self._api(self.api_key)
            result = api.ip_get(self.ip)

            return result
        else:
            raise MaltiverseIOCError("/ip/ endpoint requires a valid IPv4 address!")

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of query result
        """
        if self.url:
            api = self._api(self.api_key)
            result = api.url_get(self.url)

            return result
        else:
            raise MaltiverseIOCError("/url/ endpoint requires a valid URL!")


class MISP(Domain, EmailAddress, FileHash, IPAddress, URL):
    """MISP Threat Intel Platform

    The MISP threat sharing platform is a free and open source software helping
     information sharing of threat intelligence including cyber security
     indicators.
    """
    def __init__(self, api_key: str, api_url: str):
        """
        :param api_key: MISP API key
        :param api_url: MISP API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        EmailAddress.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api(self, ssl: bool) -> pymisp.PyMISP:
        """Instantiates ExpandedPyMISP API

        :param ssl: True/False verify certificate
        :return: PyMISP API client
        """
        m = ExpandedPyMISP(self.api_url, self.api_key, ssl=ssl)

        return m

    def _search_params(self, iocvalue: str, limit: int, warninglist: bool) -> Dict:
        """Sets parameters for search query

        :param iocvalue: IOC value
        :param limit: number of results
        :param warninglist: enforce MISP warninglist
        :return: dict
        """
        params = {"value": iocvalue, "limit": limit, "enforce_warninglist": warninglist}

        return params

    def check_domain(self, ssl: bool = True, limit: int = 50, warninglist: bool = True) -> List[Dict]:
        """Checks Domain reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list of MISP events
        """
        params = self._search_params(self.domain, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_email(self, ssl: bool = True, limit: int = 50, warninglist: bool = True) -> List[Dict]:
        """Checks Email Address reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list of MISP events
        """
        params = self._search_params(self.email, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_hash(self, ssl: bool = True, limit: int = 50, warninglist: bool = True) -> List[Dict]:
        """Checks File Hash reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list of MISP events
        """
        params = self._search_params(self.file_hash, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_ip(self, ssl: bool = True, limit: int = 50, warninglist: bool = True) -> List[Dict]:
        """Checks IP reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list of MISP events
        """
        params = self._search_params(self.ip, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_url(self, ssl: bool = True, limit: int = 50, warninglist: bool = True) -> List[Dict]:
        """Checks URL reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list of MISP events
        """
        params = self._search_params(self.url, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search


class Onyphe(Domain, IPAddress):
    """Onyphe Cyber Defense Search Engine

    ONYPHE is a cyber defense search engine for opensource and threat intelligence
    data collected by crawling various sources available on the internet or by
    listening to internet background noise.
    """
    def __init__(self, api_key: str, api_url: str = "https://www.onyphe.io/api/v2/"):
        """
        :param api_key: Onyphe API key
        :param api_url: Onyphe API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str) -> Dict:
        """Get request to API

        :param endpoint: Onyphe API endpoint
        :return: dict of request response
        """
        headers = {
            "Authorization": f"apikey {self.api_key}",
            "Content-Type": "application/json",
        }

        response = requests.request("GET", url=endpoint, headers=headers)

        return response.json()

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of request response
        """
        url = f"{self.api_url}summary/domain/{self.domain}"
        response = self._api_get(url)

        return response

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of request response
        """
        url = f"{self.api_url}summary/ip/{self.ip}"
        response = self._api_get(url)

        return response


class OTX(Domain, FileHash, IPAddress, URL):
    """OTX Open Threat Exchange

    AlienVault OTX is a threat data platform that allows security researchers
    and threat data producers to share research and investigate new threats.
    """
    def __init__(self, api_key: str):
        """
        :param api_key: OTX API key
        """
        Domain.__init__(self, api_key=api_key)
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)
        URL.__init__(self, api_key=api_key)

    def _api(self) -> OTXv2:
        """Instantiates OTXv2 API

        :return: OTXv2 API client
        """
        api = OTXv2(api_key=self.api_key)

        return api

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of query result
        """
        api = self._api()
        if self.domain:
            return api.get_indicator_details_full(IndicatorTypes.DOMAIN, self.domain)

        else:
            raise OTXError(
                "/api/v1/indicators/domain/{domain}/{section} endpoint requires a valid domain!"
            )

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        :return: dict of query results
        """
        api = self._api()

        if get_hash_type(self.file_hash) == "MD5":
            return api.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_MD5, self.file_hash
            )

        elif get_hash_type(self.file_hash) == "SHA-1":
            return api.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_SHA1, self.file_hash
            )

        elif get_hash_type(self.file_hash) == "SHA-256":
            return api.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_SHA256, self.file_hash
            )

        else:
            raise OTXError(
                "/api/v1/indicators/file/{file_hash}/{section} endpoint requires a valid MD5, SHA1 or SHA256 hash!"
            )

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of query results
        """
        api = self._api()
        if self.ip:
            return api.get_indicator_details_full(IndicatorTypes.IPv4, self.ip)
        else:
            raise OTXError(
                "/api/v1/indicators/IPv4/{ip}/{section} endpoint requires a valid IPv4 address!"
            )

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of query results
        """
        api = self._api()
        if self.url:
            return api.get_indicator_details_full(IndicatorTypes.URL, self.url)
        else:
            raise OTXError(
                "/api/v1/indicators/url/{url}/{section} endpoint requires a valid URL!"
            )


class Pulsedive(Domain, IPAddress):
    """Pulsedive Threat Intelligence Made Easy

    Pulsedive is a free threat intelligence platform. Search, scan, and enrich IPs, URLs, domains and other IOCs from OSINT feeds or submit your own.
    """
    def __init__(self, api_key: str, api_url: str = "https://pulsedive.com/api/"):
        """
        :param api_key: Pulsedive API key
        :param api_url: Pulsedive API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str, iocvalue: str) -> Dict:
        """GET request to API

        :param endpoint: Pulsedive API endpoint for query
        :param iocvalue: domain or ip
        :return: dict of request response
        """
        params = {"indicator": iocvalue, "key": self.api_key}
        info = self.api_url + endpoint

        response = requests.request("GET", url=info, params=params)

        return response.json()

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of request response
        """
        return self._api_get(endpoint="info.php", iocvalue=self.domain)

    def check_ip(self) -> Dict:
        """Checks IP Address reputation

        :return: dict of request response
        """
        return self._api_get(endpoint="info.php", iocvalue=self.ip)


class URLhaus(Domain, FileHash, IPAddress, URL):
    """URLhaus Malware URL Exchange

    URLhaus is a project from abuse.ch with the goal of collecting, tracking,
    and sharing malicious URLs that are being used for malware distribution.
    """
    def __init__(self, api_url: str = "https://urlhaus-api.abuse.ch/v1/", url_id: str = None):
        """
        :param api_url: URLhaus API URL
        :param url_id: search by URLhaus urlid
        """
        self._url_id = url_id
        Domain.__init__(self, api_url=api_url)
        FileHash.__init__(self, api_url=api_url)
        IPAddress.__init__(self, api_url=api_url)
        URL.__init__(self, api_url=api_url)

    @property
    def url_id(self):
        return self._url_id

    @url_id.setter
    def url_id(self, value):
        self._url_id = value

    def _api_post(self, endpoint: str, ioctype: str, iocvalue: str) -> Dict:
        """POST request to API

        :param endpoint: Urlhaus API endpoint
        :param ioctype: host, md5_hash, sha256_hash, or url
        :param iocvalue: domain, ip addresses, hostname, filehash, url
        :return: dict of request response
        """
        data = {ioctype: iocvalue}

        response = requests.request("POST", url=endpoint, data=data)

        return response.json()

    def _check_host(self, ioc) -> Dict:
        """POST request to /host/ endpoint

        :param ioc: domain, ip address, hostname, filehash, url
        :return: dict of request response
        """
        response = self._api_post(f"{self.api_url}host/", "host", ioc)

        return response

    def check_domain(self) -> Dict:
        """Checks Domain reputation

        :return: dict of request response
        """
        return self._check_host(self.domain)

    def check_hash(self) -> Dict:
        """Checks File Hash reputation

        :return: dict of request response
        """
        if get_hash_type(self.file_hash) == "MD5":
            response = self._api_post(
                f"{self.api_url}payload/", "md5_hash", self.file_hash
            )
        elif get_hash_type(self.file_hash) == "SHA-256":
            response = self._api_post(
                f"{self.api_url}payload/", "sha256_hash", self.file_hash
            )
        else:
            raise URLhausHashError(
                "/payload/ endpoint requires a valid MD5 or SHA-256 hash!"
            )

        return response

    def check_ip(self) -> Dict:
        """Checks IP reputation

        :return: dict of request response
        """
        return self._check_host(self.ip)

    def check_url(self) -> Dict:
        """Checks URL reputation

        :return: dict of request response
        """
        if not self.url_id and self.url:
            response = self._api_post(f"{self.api_url}url/", "url", self.url)

            return response
        elif not self.url and self.url_id:
            response = self._api_post(f"{self.api_url}urlid/", "urlid", self.url_id)

            return response
        else:
            raise PyOTIError(
                "You must supply either an urlid or URL to check, but not both!"
            )


class URLscan(Domain, FileHash, IPAddress, URL):
    """URLscan a sanbox for the web

    URLscan is a free service to scan and analyse websites.
    """
    def __init__(self, api_key: str, api_url: str = "https://urlscan.io/api/v1/", id=None):
        self._id = id
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self,  api_key=api_key, api_url=api_url)
        IPAddress.__init__(self,  api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    def _api_get(self, endpoint: str, params: Dict) -> Dict:
        """GET request to urlscan API

        :param endpoint: urlscan API endpoint
        :param params: params for request
        :return: dict of request response
        """
        rparams = params

        uri = self.api_url + endpoint
        response = requests.request("GET", url=uri, params=rparams)

        return response.json()

    def _escape_url(self, url: str) -> str:
        """Escape URL for elastic syntax

        :param url: url to escape
        :return: escaped url for elastic syntax
        """
        url = url.replace(":", "\:")
        url = url.replace("/", "\/")

        return url

    def search_domain(self, contacted: bool = False, limit: int = 100) -> Dict:
        """
        :param contacted: default False (domain was contacted but isn't the page/primary domain)
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        if contacted:
            params = {"q": f"domain:{self.domain} AND NOT page.domain:{self.domain}", "size": limit}
        else:
            params = {"q": f"domain:{self.domain}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def search_hash(self, limit: int = 100) -> Dict:
        """
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        params = {"q": f"hash:{self.file_hash}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def search_ip(self, limit: int = 100) -> Dict:
        """
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        params = {"q": f"page.ip:{self.ip}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def search_url(self, limit: int = 100) -> Dict:
        """
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        params = {"q": f"task.url:{self._escape_url(self.url)}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def check_domain(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_domain method to get result UUID.")

    def check_hash(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_hash method to get result UUID.")

    def check_ip(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_ip method to get result UUID.")

    def check_url(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_url method to get result UUID.")


class VirusTotalV2(Domain, FileHash, IPAddress, URL):
    """VirusTotal IOC Analyzer

    VirusTotal analyzes files and URLs enabling detection of malicious content
    using antivirus engines and website scanners. (VT API v2)
    """
    def __init__(
        self, api_key: str, api_url: str = "https://www.virustotal.com/vtapi/v2/"
    ):
        """
        :param api_key: VirusTotal API key
        :param api_url: VirusTotal v2 API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str, ioctype: str, iocvalue: str, allinfo: bool, scan: bool = None) -> Dict:
        """GET request to API

        :param endpoint: VirusTotal v2 API endpoint
        :param ioctype: domain, resource, or ip
        :param iocvalue: domain, filehash, ip address, URL
        :param allinfo: more details with VT premium
        :param scan: submit URL for analysis if no report is found
        :return: dict of request response
        """
        params = {"apikey": self.api_key, ioctype: iocvalue}
        if allinfo:
            params["allinfo"] = True
        if scan:
            params["scan"] = 1

        response = requests.request("GET", url=endpoint, params=params)

        return response.json()

    def check_domain(self, allinfo: bool = False) -> Dict:
        """Checks Domain reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :return: dict of request response
        """
        url = f"{self.api_url}domain/report"
        response = self._api_get(url, "domain", self.domain, allinfo)

        return response

    def check_hash(self, allinfo: bool = False, scan_id: bool = None) -> Dict:
        """Checks File Hash Reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup by scan_id (returned by the /file/scan endpoint).
        :return: dict of request response
        """
        url = f"{self.api_url}file/report"
        if get_hash_type(self.file_hash) == "MD5" or "SHA-1" or "SHA-256":
            response = self._api_get(url, "resource", self.file_hash, allinfo)
        elif not self.file_hash and scan_id:
            response = self._api_get(url, "resource", scan_id, allinfo)
        else:
            raise VirusTotalError(
                "/file/report endpoint requires a valid MD5/SHA1/SHA256 hash or scan_id!"
            )

        return response

    def check_ip(self, allinfo: bool = False) -> Dict:
        """Checks IP reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :return: dict of request response
        """
        url = f"{self.api_url}ip-address/report"
        if self.ip:
            response = self._api_get(url, "ip", self.ip, allinfo)

            return response
        else:
            raise VirusTotalError(
                "/ip-address/report endpoint requires a valid IP address!"
            )

    def check_url(self, allinfo: bool = False, scan_id: str = None, scan: bool = None) -> Dict:
        """Checks URL reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup by scan_id (returned by the /url/scan endpoint).
        :param scan: Default: None. Set True to submit URL for analysis if no report is found in VT database.
        :return: dict of request response
        """
        url = f"{self.api_url}url/report"
        if self.url:
            response = self._api_get(url, "resource", self.url, allinfo, scan)
        elif not self.url and scan_id:
            response = self._api_get(url, "resource", scan_id, allinfo, scan)
        elif self.url and not scan_id and scan:
            response = self._api_get(url, "resource", scan_id, allinfo, scan)
            sid = response["scan_id"]
            # sleep 5 seconds while VT scans URL before querying for results
            time.sleep(5)
            response = self._api_get(url, "resource", sid, allinfo, scan)
        else:
            raise VirusTotalError(
                "/url/report endpoint requires a valid URL or scan_id!"
            )

        return response


class VirusTotalV3(Domain, FileHash, IPAddress, URL):
    """VirusTotal IOC Analyzer

    VirusTotal analyzes files and URLs enabling detection of malicious content
    using antivirus engines and website scanners. (VT API v3)
    """
    def __init__(
        self, api_key, api_url="https://www.virustotal.com/api/v3"
    ):
        """
        :param api_key: VirusTotal API key
        :param api_url: VirusTotal v3 API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str) -> Dict:
        """GET request to API

        :param url: VirusTotal API endpoint URL
        :return: dict of request response
        """
        headers = {'x-apikey': self.api_key}

        response = requests.request("GET", url=url, headers=headers)

        return response.json()

    def check_domain(self) -> Dict:
        """Retrieve information about an Internet domain

        :return: dict of request response
        """
        if self.domain:
            url = f"{self.api_url}/domains/{self.domain}"
            response = self._api_get(url=url)

            return response

    def check_hash(self) -> Dict:
        """Retrieve information about a file

        :return: dict of request response
        """
        if get_hash_type(self.file_hash) == "MD5" or "SHA-1" or "SHA-256":
            url = f"{self.api_url}/files/{self.file_hash}"
            response = self._api_get(url=url)

            return response
        else:
            raise VirusTotalError(
                "/files/{id} endpoint requires a valid MD5/SHA1/SHA256 hash or scan_id!"
            )

    def check_ip(self) -> Dict:
        """Retrieve information about an IP address

        :return: dict of request response
        """
        if self.ip:
            url = f"{self.api_url}/ip_addresses/{self.ip}"
            response = self._api_get(url=url)

            return response

    def check_url(self) -> Dict:
        """Retrieve information about a URL

        :return: dict of request response
        """
        if self.url:
            url_id = base64.urlsafe_b64encode(self.url.encode()).decode().strip("=")
            url = f"{self.api_url}/urls/{url_id}"
            response = self._api_get(url=url)

            return response
