import aiodns
import asyncio
import pypssl
import requests

from maltiverse import Maltiverse
from OTXv2 import OTXv2, IndicatorTypes
from pymisp import ExpandedPyMISP

from pyoti.classes import Domain, EmailAddress, FileHash, IPAddress, URL
from pyoti.exceptions import MaltiverseIOCError, OTXError, PyOTIError, SpamhausError, URLhausHashError, VirusTotalError
from pyoti.keys import circlpassive, maltiverse, misp, onyphe, otx, virustotal
from pyoti.utils import get_hash_type


class CIRCLPSSL(FileHash, IPAddress):
    """CIRCLPSSL Historical X.509 Certificates

    CIRCL Passive SSL stores historical X.509 certificates seen per IP address.
    """

    def __init__(self, api_key=circlpassive):
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

    RBL = { # IP-Based Zones
        'b.barracudacentral.org',
        'bl.spamcop.net',
        'zen.spamhaus.org'
    }

    DBL = { # Domain-Based Zones
        'dbl.spamhaus.org',
        'multi.uribl.com',
        'multi.surbl.org'
    }

    def check_domain(self):
        """Checks Domain reputation

        Checks DNS lookup query for a given domain and maps return codes to
        appropriate data source.

        :return: dict
        """
        result_list = []
        for dbl in self.DBL:
            answer = self._resolve(blocklist=dbl, type='domain')
            if answer:
                results = {}
                bl = dbl.split(".")[1]
                if answer[0].host in ['127.0.1.2']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-spam"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.4']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-phish"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.5']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-malware"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.6']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-botnet-c2"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.102']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-legit"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.103']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-redirector"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.104']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-phish"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.105']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-malware"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.106']:
                    results["address"] = answer[0].host
                    results["blocklist"] = f"{bl}-abused-botnet-c2"

                    result_list.append(results)
                elif answer[0].host in ['127.0.1.255']:
                    raise SpamhausError("IP queries prohibited!")
                elif answer[0].host in ['127.255.255.252', '127.255.255.254', '127.255.255.255']:
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
            answer = self._resolve(blocklist=rbl, type='ip')
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
        rev = '.'.join(reversed(str(ipaddr).split(".")))

        return rev

    def _resolve(self, blocklist, type):
        """Performs reverse DNS lookup"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            resolver = aiodns.DNSResolver(loop=loop, nameservers=['9.9.9.9'])

            async def query(name, query_type):
                return await resolver.query(name, query_type)

            if type == 'ip':
                coro = query(f'{self._reverse_ip(ipaddr=self.ip)}.{blocklist}', 'A')
            elif type == 'domain':
                coro = query(f'{self.domain}.{blocklist}', 'A')

            result = loop.run_until_complete(coro)

            return result

        except aiodns.error.DNSError:
            return


class MaltiverseIOC(Domain, FileHash, IPAddress, URL):
    """MaltiverseIOC IOC Search Engine

    Maltiverse is an open IOC search engine providing collective intelligence.
    """

    def __init__(self, api_key=maltiverse):
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
        if get_hash_type(self.file_hash) == 'MD5':
            result = api.sample_get_by_md5(self.file_hash)

            return result
        elif get_hash_type(self.file_hash) == 'SHA-256':
            result = api.sample_get(self.file_hash)

            return result
        else:
            raise MaltiverseIOCError("/sample/ endpoint requires a valid MD5 or SHA256 hash!")

    def check_ip(self):
        """Checks IP reputation"""

        if self.ip:
            api = self._api(self.api_key)
            result = api.ip_get(self.ip)

            return result
        else:
            raise MaltiverseIOCError('/ip/ endpoint requires a valid IPv4 address!')

    def check_url(self):
        """Checks URL reputation"""

        if self.url:
            api = self._api(self.api_key)
            result =  api.url_get(self.url)

            return result
        else:
            raise MaltiverseIOCError("/url/ endpoint requires a valid URL!")


class MISP(Domain, EmailAddress, FileHash, IPAddress, URL):
    """MISP Threat Intel Platform

    The MISP threat sharing platform is a free and open source software helping
     information sharing of threat intelligence including cyber security
     indicators.
    """

    def __init__(self, api_key=misp):
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
        params = {'value': iocvalue, 'limit': limit, 'enforce_warninglist': warninglist}

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

    def __init__(self, api_key=onyphe, api_url="https://www.onyphe.io/api/v2/"):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint):
        """Get request to API"""

        headers = {
            'Authorization': f"apikey {self.api_key}",
            'Content-Type': 'application/json'
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

    def __init__(self, api_key=otx):
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
            raise OTXError("/api/v1/indicators/domain/{domain}/{section} endpoint requires a valid domain!")

    def check_hash(self):
        """Checks File Hash reputation

        :return: dict
        """

        api = self._api()

        if get_hash_type(self.file_hash) == 'MD5':
            return api.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, self.file_hash)

        elif get_hash_type(self.file_hash) == 'SHA-1':
            return api.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1, self.file_hash)

        elif get_hash_type(self.file_hash) == 'SHA-256':
            return api.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, self.file_hash)

        else:
            raise OTXError("/api/v1/indicators/file/{file_hash}/{section} endpoint requires a valid MD5, SHA1 or SHA256 hash!")

    def check_ip(self):
        """Checks IP reputation

        :return: dict
        """

        api = self._api()
        if self.ip:
            return api.get_indicator_details_full(IndicatorTypes.IPv4, self.ip)
        else:
            raise OTXError("/api/v1/indicators/IPv4/{ip}/{section} endpoint requires a valid IPv4 address!")

    def check_url(self):
        """Checks URL reputation

        :return: dict
        """

        api = self._api()
        if self.url:
            return api.get_indicator_details_full(IndicatorTypes.URL, self.url)
        else:
            raise OTXError("/api/v1/indicators/url/{url}/{section} endpoint requires a valid URL!")


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

        data = {
            ioctype: iocvalue
        }

        response = requests.request("POST", url=endpoint, data=data)

        return response.json()

    def _check_host(self, ioc):
        """POST request to /host/ endpoint"""

        response = self._api_post(f'{self.api_url}host/', 'host', ioc)

        return response

    def check_domain(self):
        """Checks Domain reputation"""

        return self._check_host(self.domain)

    def check_hash(self):
        """Checks File Hash reputation"""

        if get_hash_type(self.file_hash) == 'MD5':
            response = self._api_post(f'{self.api_url}payload/', 'md5_hash', self.file_hash)
        elif get_hash_type(self.file_hash) == 'SHA-256':
            response = self._api_post(f'{self.api_url}payload/', 'sha256_hash', self.file_hash)
        else:
            raise URLhausHashError("/payload/ endpoint requires a valid MD5 or SHA-256 hash!")

        return response.json()

    def check_ip(self):
        """Checks IP reputation"""

        return self._check_host(self.ip)

    def check_url(self):
        """Checks URL reputation"""

        if not self.url_id and self.url:
            response = self._api_post(f'{self.api_url}url/', 'url', self.url)

            return response.json()
        elif not self.url and self.url_id:
            response = self._api_post(f'{self.api_url}urlid/', 'urlid', self.url_id)

            return response.json()
        else:
            raise PyOTIError("You must supply either an urlid or URL to check, but not both!")


class VirusTotal(Domain, FileHash, IPAddress, URL):
    """VirusTotal IOC Analyzer

    VirusTotal analyzes files and URLs enabling detection of malicious content
    using antivirus engines and website scanners.
    """

    def __init__(self, api_key=virustotal, api_url="https://www.virustotal.com/vtapi/v2/"):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint, ioctype, iocvalue, allinfo):
        """GET request to API"""

        params = {
            'apikey': self.api_key,
            ioctype: iocvalue
        }
        if allinfo is True:
            params['allinfo'] = True

        response = requests.request("GET", url=endpoint, params=params)

        return response.json()

    def check_domain(self, allinfo=False):
        """Checks Domain reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        """

        url = f'{self.api_url}domain/report'
        response = self._api_get(url, 'domain', self.domain, allinfo)

        return response

    def check_hash(self, allinfo=False, scan_id=None):
        """Checks File Hash Reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup an already submitted
        resource instead of looking up by file hash.
        """

        url = f'{self.api_url}file/report'
        if get_hash_type(self.file_hash) == 'MD5' or 'SHA-1' or 'SHA-256':
            response = self._api_get(url, 'resource', self.file_hash, allinfo)
        elif not self.file_hash and scan_id:
            response = self._api_get(url, 'resource', scan_id, allinfo)
        else:
            raise VirusTotalError("/file/report endpoint requires a valid MD5/SHA1/SHA256 hash or scan_id!")

        return response

    def check_ip(self, allinfo=False):
        """Checks IP reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        """

        url = f'{self.api_url}ip-address/report'
        if self.ip:
            response = self._api_get(url, 'ip', self.ip, allinfo)

            return response
        else:
            raise VirusTotalError("/ip-address/report endpoint requires a valid IP address!")

    def check_url(self, allinfo=False, scan_id=None):
        """Checks URL reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup an already submitted
        resource instead of looking up by URL.
        """

        url = f'{self.api_url}url/report'
        if self.url:
            response = self._api_get(url, 'resource', self.url, allinfo)
        elif not self.url and scan_id:
            response = self._api_get(url, 'resource', scan_id, allinfo)
        else:
            raise VirusTotalError("/url/report endpoint requires a valid URL or scan_id!")

        return response
