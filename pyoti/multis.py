import pypssl
import requests

from maltiverse import Maltiverse
from OTXv2 import OTXv2, IndicatorTypes

from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import MaltiverseIOCError, OTXError, URLhausHashError, VirusTotalDomainError, VirusTotalHashError, VirusTotalIPError, VirusTotalURLError
from pyoti.keys import circlpassive, maltiverse, onyphe, otx, virustotal
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
        """

        pssl = self._api()
        query = pssl.query(self.ip)

        return query

    def check_hash(self):
        """Checks File Hash reputation

        Checks CIRCL Passive SSL for historical X.509 certificates for a given
        certificate fingerprint.
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
        cfetch = pssl.fetch_cert(self.file_hash)

        # still need to verify if this returns a list or dict
        return cfetch


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
        """Checks Domain reputation"""

        url = f"{self.api_url}summary/domain/{self.domain}"
        response = self._api_get(url)

        return response

    def check_ip(self):
        """Checks IP reputation"""

        url = f"{self.api_url}summary/ip/{self.ip}"
        response = self._api_get(url)

        return response


class OTX(Domain, FileHash, IPAddress):
    """OTX Open Threat Exchange

    AlienVault OTX is a threat data platform that allows security researchers
    and threat data producers to share research and investigate new threats.
    """

    def _api(self):
        """Instantiates OTXv2 API"""

        api = OTXv2(api_key=otx)

        return api

    def check_domain(self):
        """Checks Domain reputation"""

        api = self._api()
        if self.domain:
            return api.get_indicator_details_full(IndicatorTypes.DOMAIN, self.domain)

        else:
            raise OTXError("/api/v1/indicators/domain/{domain}/{section} endpoint requires a valid domain!")

    def check_hash(self):
        """Checks File Hash reputation"""

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
        """Checks IP reputation"""

        api = self._api()
        if self.ip:
            return api.get_indicator_details_full(IndicatorTypes.IPv4, self.ip)
        else:
            raise OTXError("/api/v1/indicators/IPv4/{ip}/{section} endpoint requires a valid IPv4 address!")

    def check_url(self):
        """Checks URL reputation"""

        api = self._api()
        if self.url:
            return api.get_indicator_details_full(IndicatorTypes.URL, self.url)
        else:
            raise OTXError("/api/v1/indicators/url/{url}/{section} endpoint requires a valid URL!")


class URLhaus(Domain, FileHash, IPAddress, URL):
    """URLhaus Malware URL Exchange

    URLhaus is a project from abuse.ch with the goal of collecting, tracking,
    and sharing malicious URLs that are being used for malware distribution.
    """

    def __init__(self, api_url="https://urlhaus-api.abuse.ch/v1/", url_id=None):
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
        response = self._api_post(f'{self.api_url}url/', 'url', self.url)

        return response.json()


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
            raise VirusTotalHashError("/file/report endpoint requires a valid MD5/SHA1/SHA256 hash or scan_id!")

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
            raise VirusTotalIPError("/ip-address/report endpoint requires a valid IP address!")

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
            raise VirusTotalURLError("/url/report endpoint requires a valid URL or scan_id!")

        return response
