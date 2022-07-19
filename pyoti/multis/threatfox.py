import requests
from typing import Dict, List, Union

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import PyOTIError


class ThreatFox(Domain, FileHash, IPAddress, URL):
    """ThreatFox by abuse.ch

    ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs) associated with
    malware with the infosec community, AV vendors and threat intelligence providers
    """
    def __init__(self, api_key: str, api_url: str = "https://threatfox-api.abuse.ch/api/v1"):
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_post(self, data) -> requests.models.Response:
        """POST request to ThreatFox API"""
        headers = {
            "API-KEY": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("POST", url=self.api_url, headers=headers, json=data)

        return response

    def _sort_results(self, result: List[Dict]) -> List[Dict]:
        """Sorts ThreatFox results

        :param result: list of results from API request
        :return: list of results from API request sorted in descending order of first_seen
        """
        sorted_result = sorted(result, key=lambda k: k['first_seen'], reverse=True)

        return sorted_result

    def check_domain(self) -> Union[Dict, List[Dict]]:
        """Checks Domain reputation"""
        data = {"query": "search_ioc", "search_term": self.domain}

        response = self._api_post(data=data)

        if response.json().get("query_status") == "no_result":
            return response.json()
        else:
            to_return = self._sort_results(result=response.json().get("data"))

            return to_return

    def check_hash(self) -> Union[Dict, List[Dict]]:
        """Checks File Hash reputation"""
        if len(self.file_hash) == 32 or len(self.file_hash) == 64:
            data = {"query": "search_ioc", "search_term": self.file_hash}
        else:
            raise PyOTIError("You must supply MD5 or SHA256 hash to query ThreatFox.")

        response = self._api_post(data=data)

        if response.json().get("query_status") == "no_result":
            return response.json()
        else:
            to_return = self._sort_results(result=response.json().get("data"))

            return to_return

    def check_hash_associated_iocs(self) -> Union[Dict, List[Dict]]:
        """Checks for IOCs associated with a certain File Hash"""
        if len(self.file_hash) == 32 or len(self.file_hash) == 64:
            data = {"query": "search_hash", "hash": self.file_hash}
        else:
            raise PyOTIError("You must supply MD5 or SHA256 hash to query ThreatFox.")

        response = self._api_post(data=data)

        if response.json().get("query_status") == "no_result":
            return response.json()
        else:
            to_return = self._sort_results(result=response.json().get("data"))

            return to_return

    def check_ip(self) -> Union[Dict, List[Dict]]:
        """Checks IP Address reputation"""
        data = {"query": "search_ioc", "search_term": self.ip}

        response = self._api_post(data=data)

        if response.json().get("query_status") == "no_result":
            return response.json()
        else:
            to_return = self._sort_results(result=response.json().get("data"))

            return to_return

    def check_url(self) -> Union[Dict, List[Dict]]:
        """Checks URL reputation"""
        data = {"query": "search_ioc", "search_term": self.url}

        response = self._api_post(data=data)

        if response.json().get("query_status") == "no_result":
            return response.json()
        else:
            to_return = self._sort_results(result=response.json().get("data"))

            return to_return
