import pypssl
import requests

from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import URLhausHashError, VirusTotalDomainError, VirusTotalHashError, VirusTotalIPError, VirusTotalURLError
from pyoti.keys import circlpassive, virustotal
from pyoti.utils import get_hash_type


class CIRCLPSSL(FileHash, IPAddress):
    def __init__(self, api_key=circlpassive):
        FileHash.__init__(self, api_key=api_key)
        IPAddress.__init__(self, api_key=api_key)

    def _pyssl(self):
        credentials = self.api_key.split(":")
        pssl = pypssl.PyPSSL(basic_auth=(credentials[0], credentials[1]))

        return pssl

    def check_ip(self):
        pssl = self._pyssl()
        query = pssl.query(self.ip)

        return query

    def check_hash(self):
        pssl = self._pyssl()
        cquery = pssl.query_cert(self.file_hash)

        return cquery

    def fetch_cert(self):
        pssl = self._pyssl()
        cfetch = pssl.fetch_cert(self.file_hash)

        # still need to verify if this returns a list or dict
        return cfetch


class URLhaus(Domain, FileHash, IPAddress, URL):
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

    def _check_host(self, ioc):
        data = {
            'host': ioc
        }

        response = requests.request("POST", url=f'{self.api_url}host/', data=data)

        return response.json()

    def check_domain(self):
        return self._check_host(self.domain)

    def check_hash(self):
        if get_hash_type(self.file_hash) == 'MD5':
            data = {
                'md5_hash': self.file_hash
            }
        elif get_hash_type(self.file_hash) == 'SHA-256':
            data = {
                'sha256_hash': self.file_hash
            }
        else:
            raise URLhausHashError("/payload/ endpoint requires a valid MD5 or SHA-256 hash!")

        response = requests.request("POST", url=f'{self.api_url}payload/', data=data)

        return response.json()

    def check_ip(self):
        return self._check_host(self.ip)

    def check_url(self):
        data = {
            'url': self.url
        }

        response = requests.request("POST", url=f'{self.api_url}url/', data=data)

        return response.json()


class VirusTotal(Domain, FileHash, IPAddress, URL):
    def __init__(self, api_key=virustotal, api_url="https://www.virustotal.com/vtapi/v2/"):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def check_domain(self):
        url = f'{self.api_url}domain/report'
        if self.domain:
            params = {
                'apikey': self.api_key,
                'domain': self.domain
            }
            response = requests.request("GET", url=url, params=params)

            return response.json()
        else:
            raise VirusTotalDomainError("/domain/report endpoint requires a valid domain!")

    def check_hash(self, allinfo=False, scan_id=None):
        url = f'{self.api_url}file/report'
        if get_hash_type(self.file_hash) == 'MD5' or 'SHA-1' or 'SHA-256':
            params = {
                'apikey': self.api_key,
                'resource': self.file_hash
            }
            if allinfo:
                params['allinfo'] = True
        elif not self.file_hash and scan_id:
            params = {
                'apikey': self.api_key,
                'resource': scan_id
            }
            if allinfo:
                params['allinfo'] = True
        else:
            raise VirusTotalHashError("/file/report endpoint requires a valid MD5/SHA1/SHA256 hash or scan_id!")

        response = requests.request("GET", url=url, params=params)

        return response.json()

    def check_ip(self):
        url = f'{self.api_url}ip-address/report'
        if self.ip:
            params = {
                'apikey': self.api_key,
                'ip': self.ip
            }
            response = requests.request("GET", url=url, params=params)

            return response.json()
        else:
            raise VirusTotalIPError("/ip-address/report endpoint requires a valid IP address!")

    def check_url(self, allinfo=False, scan_id=None):
        url = f'{self.api_url}url/report'
        if self.url:
            params = {
                'apikey': self.api_key,
                'resource': self.url
            }
            if allinfo:
                params['allinfo'] = True
        elif not self.url and scan_id:
            params = {
                'apikey': self.api_key,
                'resource': scan_id
            }
            if allinfo:
                params['allinfo'] = True
        else:
            raise VirusTotalURLError("/url/report endpoint requires a valid URL or scan_id!")

        response = requests.request("GET", url=url, params=params)

        return response.json()
