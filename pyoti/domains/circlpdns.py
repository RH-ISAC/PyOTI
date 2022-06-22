import json
import requests
from typing import Dict, List, Union

from pyoti import __version__
from pyoti.classes import Domain
from pyoti.exceptions import CIRCLPDNSError
from pyoti.utils import epoch_to_date


class CIRCLPDNS(Domain):
    """CIRCLPDNS Historical DNS Records

    CIRCL Passive DNS stores historical DNS records from various resources including malware analysis or partners.
    """
    def __init__(self, api_key: str, api_url: str = "https://www.circl.lu/pdns/query"):
        """
        :param api_key: CIRCLPDNS API key
        :param api_url: CIRCLPDNS base API URL
        """
        self.sort_choice = ['count', 'rdata', 'rrname', 'rrtype', 'time_first', 'time_last']
        Domain.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self) -> Union[requests.models.Response, Dict]:
        """GET request to API"""
        credentials = self.api_key.split(":")

        headers = {"User-Agent": f"PyOTI {__version__}"}

        response = requests.request(
            "GET",
            url=f"{self.api_url}/{self.domain}",
            auth=(credentials[0], credentials[1]),
            headers=headers)

        if response.status_code != 200:
            if response.status_code == 401:
                return {"error": {f"{response.status_code}": "Not authenticated: is authentication correct?"}}
            elif response.status_code == 403:
                return {"error": {f"{response.status_code}": "Not authorized to access resource!"}}
            elif response.status_code == 429:
                return {"error": {f"{response.status_code}": "Quota exhausted!"}}
            elif 500 <= response.status_code < 600:
                return {"error": {f"{response.status_code}": "Server error!"}}
            else:
                return {"error": "Something went wrong!"}

        return response

    def check_domain(self, sort_by: str = "time_last") -> List[Dict]:
        """Checks domain reputation

        Checks CIRCL Passive DNS for historial DNS records for a given domain.

        :param sort_by: how returned data should be sorted
        :return: list of dicts
        """
        if sort_by not in self.sort_choice:
            raise CIRCLPDNSError(f"You can only sort by the following: {self.sort_choice}")
        response = self._api_get()

        to_return = []
        for line in response.text.split('\n'):
            if len(line) == 0:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            obj['time_first'] = epoch_to_date(obj['time_first'])
            obj['time_last'] = epoch_to_date(obj['time_last'])
            to_return.append(obj)
        to_return = sorted(to_return, key=lambda k: k[sort_by])

        return to_return
