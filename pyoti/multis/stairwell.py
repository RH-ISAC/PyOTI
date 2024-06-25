import requests
from typing import Dict, List, Optional

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

    def _api_get(self, endpoint: str, params: Optional[Dict] = None) -> requests.models.Response:
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
        response = self._api_get(endpoint=f'/objects/{self.file_hash}/metadata')

        return response.json()

    def check_ip(self) -> Dict:
        params = {'filter': f'net.ip == "{self.ip}"'}
        response = self._api_get(endpoint='/objects/metadata', params=params)

        return response.json()

    def query_objects(self, query: str, page_size: int = None) -> List[Dict]:
        """
        Fetches a list of object metadata. Objects returned match the filter specified in the request.

        :param query: CEL string filter which objects must match. https://help.stairwell.com/en/knowledge/how-do-i-write-a-cel-query
        :param page_size: The maximum number of objects to return. The service may return fewer than this value. If unspecified, at most 50 objects will be returned. The maximum value is 1000; values above 1000 will be coerced to 1000.
        """
        # TODO: async requests would likely speed this up significantly
        all_objects = []
        next_page_token = None

        while True:
            params = {
                'filter': query,
                'pageSize': page_size,
                'pageToken': next_page_token
            }
            response = self._api_get(endpoint='/objects/metadata', params=params)
            data = response.json()
            object_metadatas = data.get('objectMetadatas', [])
            all_objects.extend(object_metadatas)

            next_page_token = data.get('nextPageToken')
            if not next_page_token:
                break

        return all_objects
