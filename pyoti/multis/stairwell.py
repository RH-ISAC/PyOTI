import requests
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress


class Stairwell(Domain, FileHash, IPAddress):
    """
    Stairwell provides a unique view into your enterprise and operational environments via lightweight forwarders or
    cli utilities which leverage automated analysis, robust YARA rule libraries, shared malware feeds, privately run AV
    verdicts, static & dynamic analysis, malware unpacking, and variant discovery.
    """
    def __init__(self, api_key: str, api_url: str = "https://app.stairwell.com/v1"):
        Domain.__init__(self, api_key, api_url)
        FileHash.__init__(self, api_key, api_url)
        IPAddress.__init__(self, api_key, api_url)

    def _api_get(self, endpoint: str, params: Optional[Dict]) -> requests.models.Response:
        """GET request to Stairwell API

        :param endpoint: Stairwell API endpoint
        :param params: params for request
        """
        headers = {
            "Accept": "application/json",
            "Authorization": self.api_key,
            "User-Agent": f"PyOTI {__version__}"
        }
        rparams = params

        uri = self.api_url + endpoint
        response = requests.request("GET", url=uri, headers=headers, params=rparams)

        return response

    def check_domain(self) -> Dict:
        params = {'filter': f'net.hostname == "{self.domain}"'}

        response = self._api_get(endpoint='/objects/metadata', params=params)

        return response.json()

    def check_hash(self) -> Dict:
        params = {}
        if len(self.file_hash) == 32:
            params['filter'] = f'object.md5 == "{self.file_hash}"'
        elif len(self.file_hash) == 40:
            params['filter'] = f'object.sha1 == "{self.file_hash}"'
        elif len(self.file_hash) == 64:
            params['filter'] = f'object.sha256 == "{self.file_hash}"'

        response = self._api_get(endpoint='/objects/metadata', params=params)

        return response.json()

    def check_ip(self) -> Dict:
        params = {'filter': f'net.ip == "{self.ip}"'}
        response = self._api_get(endpoint='/objects/metadata', params=params)

        return response.json()
