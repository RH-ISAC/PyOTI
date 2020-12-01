import requests

from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import URLhausHashError
from pyoti.utils import get_hash_type


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
            raise URLhausHashError("URLhaus query only accepts MD5 or SHA-256 hash type!")

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
