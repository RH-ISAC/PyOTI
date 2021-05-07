import aiodns
import asyncio
import pypssl
import requests
import time

from maltiverse import Maltiverse
from OTXv2 import OTXv2, IndicatorTypes
from pymisp import ExpandedPyMISP

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

    def __init__(self, api_key):
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)

    def _api(self):
        """Instantiates PyPSSL API"""

        credentials = self.api_key.split(":")
        pssl = pypssl.PyPSSL(basic_auth=(credentials[0], credentials[1]))

        return pssl

    def check_ip(self):
        """Checks IP reputation

        Checks CIRCL Passive SSL for historical X.509 certificates for a given IP.

        :return: dict
        """

        pssl = self._api()
        query = pssl.query(self.ip)

        return query

    def check_hash(self):
        """Checks File Hash reputation

        Checks CIRCL Passive SSL for historical X.509 certificates for a given
        certificate fingerprint.

        :return: dict
        """

        pssl = self._api()
        cquery = pssl.query_cert(self.file_hash)

        return cquery

    def fetch_cert(self):
        """Fetch Certificate

        Fetches/parses a specified certificate from CIRCL Passive SSL for a
        given certificate fingerprint.
        """

        pssl = self._api()
        try:
            cfetch = pssl.fetch_cert(self.file_hash)
        except Exception as e:
            raise PyOTIError(e)

        # still need to verify if this returns a list or dict
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

    def check_domain(self):
        """Checks Domain reputation

        Checks DNS lookup query for a given domain and maps return codes to
        appropriate data source.

        :return: dict
        """

        result_list = []
        for dbl in self.DBL:
            answer = self._resolve(blocklist=dbl, type="domain")
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

    def check_ip(self):
        """Checks IP reputation

        Checks reverse DNS lookup query for a given IP and maps return codes to
        appropriate data source.

        :return: dict
        """

        result_list = []
        for rbl in self.RBL:
            answer = self._resolve(blocklist=rbl, type="ip")
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

    def _reverse_ip(self, ipaddr):
        """Prepares IPv4 address for reverse lookup

        :param ipaddr: IP Address
        :return: str
        """

        rev = ".".join(reversed(str(ipaddr).split(".")))

        return rev

    def _resolve(self, blocklist, type):
        """Performs reverse DNS lookup"""

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


class HybridAnalysis(FileHash, URL):
    """HybridAnalysis Malware Analysis

    HybridAnalysis is a free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology.
    """

    def __init__(
        self,
        api_key,
        api_url="https://www.hybrid-analysis.com/api/v2/",
        job_id=None,
    ):
        self._job_id = job_id
        FileHash.__init__(self, api_url=api_url, api_key=api_key)
        URL.__init__(self, api_url=api_url, api_key=api_key)

    @property
    def job_id(self):
        return self._job_id

    @job_id.setter
    def job_id(self, value):
        self._job_id = value

    def _api_post(self, endpoint, ioctype, iocvalue):
        """POST request to API"""
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PyOTI 0.1",
            "api-key": self.api_key,
        }

        data = {ioctype: iocvalue}

        uri = self.api_url + endpoint
        response = requests.request("POST", url=uri, headers=headers, data=data)

        return response.json()

    def _api_get(self, endpoint):
        """GET request to API"""
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": "PyOTI 0.1",
            "api-key": self.api_key,
        }

        uri = self.api_url + endpoint
        response = requests.request("GET", url=uri, headers=headers)

        return response.json()

    def check_hash(self):
        """Checks File Hash reputation

        :return: dict
        """
        response = self._api_post(
            endpoint="search/hash", ioctype="hash", iocvalue=self.file_hash
        )
        self.job_id = response[1]["job_id"]
        return response

    def check_url(self):
        """Checks URL reputation

        :return: dict
        """
        response = self._api_post(
            endpoint="search/terms", ioctype="url", iocvalue=self.url
        )["result"]
        self.job_id = response[0]["job_id"]
        return response

    def check_report(self, sandbox_report="summary"):
        """Checks for summary of a submission

        :param sandbox_report: default summary (see https://www.hybrid-analysis.com/docs/api/v2/)
        :return: dict
        """
        return self._api_get(endpoint=f"report/{self.job_id}/{sandbox_report}")


class MaltiverseIOC(Domain, FileHash, IPAddress, URL):
    """MaltiverseIOC IOC Search Engine

    Maltiverse is an open IOC search engine providing collective intelligence.
    """

    def __init__(self, api_key):
        Domain.__init__(self, api_key=api_key)
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)
        URL.__init__(self, api_key=api_key)

    def _api(self, auth_token):
        """Instantiates Maltiverse API"""

        api = Maltiverse(auth_token=auth_token)
        return api

    def check_domain(self):
        """Checks Domain reputation"""

        if self.domain:
            api = self._api(self.api_key)
            result = api.hostname_get(self.domain)

            return result
        else:
            raise MaltiverseIOCError("/hostname/ endpoint requires a valid domain!")

    def check_hash(self):
        """Checks File Hash reputation"""

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

    def check_ip(self):
        """Checks IP reputation"""

        if self.ip:
            api = self._api(self.api_key)
            result = api.ip_get(self.ip)

            return result
        else:
            raise MaltiverseIOCError("/ip/ endpoint requires a valid IPv4 address!")

    def check_url(self):
        """Checks URL reputation"""

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

    def __init__(self, api_key):
        Domain.__init__(self, api_key=api_key)
        EmailAddress.__init__(self, api_key=api_key)
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)
        URL.__init__(self, api_key=api_key)

    def _api(self, ssl):
        """Instantiates ExpandedPyMISP API"""

        m = ExpandedPyMISP(self.api_url, self.api_key, cert=ssl)

        return m

    def _search_params(self, iocvalue, limit, warninglist):
        """Sets parameters for search

        :param iocvalue: str
        :param limit: int
        :param warninglist: bool
        :return: dict
        """

        params = {"value": iocvalue, "limit": limit, "enforce_warninglist": warninglist}

        return params

    def check_domain(self, ssl=True, limit=50, warninglist=True):
        """Checks Domain reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list
        """

        params = self._search_params(self.domain, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_email(self, ssl=True, limit=50, warninglist=True):
        """Checks Email Address reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list
        """

        params = self._search_params(self.email, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_hash(self, ssl=True, limit=50, warninglist=True):
        """Checks File Hash reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list
        """

        params = self._search_params(self.file_hash, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_ip(self, ssl=True, limit=50, warninglist=True):
        """Checks IP reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list
        """

        params = self._search_params(self.ip, limit, warninglist)

        m_search = self._api(ssl).search(**params)

        return m_search

    def check_url(self, ssl=True, limit=50, warninglist=True):
        """Checks URL reputation

        :param ssl: verify cert. default True
        :param limit: number of results. default 50
        :param warninglist: enforce misp warninglist. default True
        :return: list
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

    def __init__(self, api_key, api_url="https://www.onyphe.io/api/v2/"):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint):
        """Get request to API"""

        headers = {
            "Authorization": f"apikey {self.api_key}",
            "Content-Type": "application/json",
        }

        response = requests.request("GET", url=endpoint, headers=headers)

        return response.json()

    def check_domain(self):
        """Checks Domain reputation

        :return: dict
        """

        url = f"{self.api_url}summary/domain/{self.domain}"
        response = self._api_get(url)

        return response

    def check_ip(self):
        """Checks IP reputation

        :return: dict
        """

        url = f"{self.api_url}summary/ip/{self.ip}"
        response = self._api_get(url)

        return response


class OTX(Domain, FileHash, IPAddress, URL):
    """OTX Open Threat Exchange

    AlienVault OTX is a threat data platform that allows security researchers
    and threat data producers to share research and investigate new threats.
    """

    def __init__(self, api_key):
        Domain.__init__(self, api_key=api_key)
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)
        URL.__init__(self, api_key=api_key)

    def _api(self):
        """Instantiates OTXv2 API"""

        api = OTXv2(api_key=self.api_key)

        return api

    def check_domain(self):
        """Checks Domain reputation

        :return: dict
        """

        api = self._api()
        if self.domain:
            return api.get_indicator_details_full(IndicatorTypes.DOMAIN, self.domain)

        else:
            raise OTXError(
                "/api/v1/indicators/domain/{domain}/{section} endpoint requires a valid domain!"
            )

    def check_hash(self):
        """Checks File Hash reputation

        :return: dict
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

    def check_ip(self):
        """Checks IP reputation

        :return: dict
        """

        api = self._api()
        if self.ip:
            return api.get_indicator_details_full(IndicatorTypes.IPv4, self.ip)
        else:
            raise OTXError(
                "/api/v1/indicators/IPv4/{ip}/{section} endpoint requires a valid IPv4 address!"
            )

    def check_url(self):
        """Checks URL reputation

        :return: dict
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

    def __init__(self, api_key, api_url="https://pulsedive.com/api/"):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint, iocvalue):
        """GET request to API"""
        params = {"indicator": iocvalue, "key": self.api_key}
        info = self.api_url + endpoint

        response = requests.request("GET", url=info, params=params)

        return response.json()

    def check_domain(self):
        """Checks Domain reputation"""
        return self._api_get(endpoint="info.php", iocvalue=self.domain)

    def check_ip(self):
        """Checks IP Address reputation"""
        return self._api_get(endpoint="info.php", iocvalue=self.ip)


class URLhaus(Domain, FileHash, IPAddress, URL):
    """URLhaus Malware URL Exchange

    URLhaus is a project from abuse.ch with the goal of collecting, tracking,
    and sharing malicious URLs that are being used for malware distribution.

    :param url_id: search by URLhaus urlid rather than URL itself
    """

    def __init__(self, api_url="https://urlhaus-api.abuse.ch/v1/", url_id=None):
        self.url_id = url_id

        Domain.__init__(self, api_url=api_url)
        FileHash.__init__(self, api_url=api_url)
        IPAddress.__init__(self, api_url=api_url)
        URL.__init__(self, api_url=api_url)

    @property
    def url_id(self):
        return self.url_id

    @url_id.setter
    def url_id(self, value):
        self.url_id = value

    def _api_post(self, endpoint, ioctype, iocvalue):
        """POST request to API"""

        data = {ioctype: iocvalue}

        response = requests.request("POST", url=endpoint, data=data)

        return response.json()

    def _check_host(self, ioc):
        """POST request to /host/ endpoint"""

        response = self._api_post(f"{self.api_url}host/", "host", ioc)

        return response

    def check_domain(self):
        """Checks Domain reputation"""

        return self._check_host(self.domain)

    def check_hash(self):
        """Checks File Hash reputation"""

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

        return response.json()

    def check_ip(self):
        """Checks IP reputation"""

        return self._check_host(self.ip)

    def check_url(self):
        """Checks URL reputation"""

        if not self.url_id and self.url:
            response = self._api_post(f"{self.api_url}url/", "url", self.url)

            return response.json()
        elif not self.url and self.url_id:
            response = self._api_post(f"{self.api_url}urlid/", "urlid", self.url_id)

            return response.json()
        else:
            raise PyOTIError(
                "You must supply either an urlid or URL to check, but not both!"
            )


class URLscan(Domain, FileHash, IPAddress, URL):
    """URLscan a sanbox for the web

    URLscan is a free service to scan and analyse websites.
    """

    def __init__(self, api_key, api_url="https://urlscan.io/api/v1/", id=None):
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

    def _api_get(self, endpoint, params):
        rparams = params

        uri = self.api_url + endpoint
        response = requests.request("GET", url=uri, params=rparams)

        return response.json()

    def _escape_url(self, url):
        """Escape URL for elastic syntax

        :param url: str
        :return: str
        """
        url = url.replace(":", "\:")
        url = url.replace("/", "\/")

        return url

    def search_domain(self, contacted=False, limit=100):
        """
        :param contacted: default False (domain was contacted but isn't the page/primary domain)
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict
        """

        if contacted:
            params = {"q": f"domain:{self.domain} AND NOT page.domain:{self.domain}", "size": limit}
        else:
            params = {"q": f"domain:{self.domain}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def search_hash(self, limit=100):
        params = {"q": f"hash:{self.file_hash}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def search_ip(self, limit=100):
        params = {"q": f"page.ip:{self.ip}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def search_url(self, limit=100):
        params = {"q": f"page.url:{self._escape_url(self.url)}", "size": limit}

        return self._api_get(endpoint="search/", params=params)

    def check_domain(self, uuid=None):
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_domain method to get result UUID.")

    def check_hash(self, uuid=None):
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_hash method to get result UUID.")

    def check_ip(self, uuid=None):
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_ip method to get result UUID.")

    def check_url(self, uuid=None):
        if uuid:
            return self._api_get(endpoint=f"result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_url method to get result UUID.")


class VirusTotal(Domain, FileHash, IPAddress, URL):
    """VirusTotal IOC Analyzer

    VirusTotal analyzes files and URLs enabling detection of malicious content
    using antivirus engines and website scanners. (VT API v2)
    """

    def __init__(
        self, api_key, api_url="https://www.virustotal.com/vtapi/v2/"
    ):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint, ioctype, iocvalue, allinfo, scan=None):
        """GET request to API"""

        params = {"apikey": self.api_key, ioctype: iocvalue}
        if allinfo:
            params["allinfo"] = True
        if scan:
            params["scan"] = 1

        response = requests.request("GET", url=endpoint, params=params)

        return response.json()

    def check_domain(self, allinfo=False):
        """Checks Domain reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :return: dict
        """

        url = f"{self.api_url}domain/report"
        response = self._api_get(url, "domain", self.domain, allinfo)

        return response

    def check_hash(self, allinfo=False, scan_id=None):
        """Checks File Hash Reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup by scan_id (returned by the /file/scan endpoint).
        :return: dict
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

    def check_ip(self, allinfo=False):
        """Checks IP reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :return: dict
        """

        url = f"{self.api_url}ip-address/report"
        if self.ip:
            response = self._api_get(url, "ip", self.ip, allinfo)

            return response
        else:
            raise VirusTotalError(
                "/ip-address/report endpoint requires a valid IP address!"
            )

    def check_url(self, allinfo=False, scan_id=None, scan=None):
        """Checks URL reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup by scan_id (returned by the /url/scan endpoint).
        :param scan: Default: None. Set True to submit URL for analysis if no report is found in VT database.
        :return: dict
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
