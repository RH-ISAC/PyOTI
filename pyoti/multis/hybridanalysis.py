import requests
from typing import Dict, List, Optional, Union

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL


class HybridAnalysis(Domain, FileHash, IPAddress, URL):
    """HybridAnalysis Malware Analysis

    HybridAnalysis is a free malware analysis service for the community that detects and analyzes unknown threats using
    a unique Hybrid Analysis technology.
    """
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://www.hybrid-analysis.com/api/v2",
        job_id: Optional[str] = None,
    ):
        """
        :param api_key: HybridAnalysis API key
        :param api_url: HybridAnalysis base API URL
        :param job_id: HybridAnalysis ID for report
        """
        self._job_id = job_id
        Domain.__init__(self, api_url=api_url, api_key=api_key)
        FileHash.__init__(self, api_url=api_url, api_key=api_key)
        IPAddress.__init__(self, api_url=api_url, api_key=api_key)
        URL.__init__(self, api_url=api_url, api_key=api_key)

    @property
    def job_id(self):
        return self._job_id

    @job_id.setter
    def job_id(self, value):
        self._job_id = value

    def _api_post(self, url: str, data: Dict) -> requests.models.Response:
        """POST request to API

        :return: dict of request response
        """
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": f"PyOTI {__version__}",
            "api-key": self.api_key,
        }

        response = requests.request("POST", url=url, headers=headers, data=data)

        return response

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API

        :return: list of dicts in request response
        """
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": f"PyOTI {__version__}",
            "api-key": self.api_key,
        }

        response = requests.request("GET", url=url, headers=headers)

        return response

    def _sort_results(self, result: List[Dict]) -> List[Dict]:
        """Sorts HybridAnalysis Results

        :param result: list of results from API request
        :return: list of results from API request sorted by last analysis time
        """
        if result:
            sorted_result = sorted(result, key=lambda k: k['analysis_start_time'], reverse=True)
            self.job_id = sorted_result[0].get("job_id") if sorted_result else None

            return sorted_result

    def check_domain(self) -> Union[List[Dict], None]:
        """Checks Domain reputation

        :return: list of dicts in request result
        """
        data = {"domain": self.domain}
        url = f"{self.api_url}/search/terms"
        response = self._api_post(url=url, data=data)
        sorted_result = self._sort_results(result=response.json().get("result"))

        return sorted_result

    def check_ip(self) -> Union[List[Dict], None]:
        """Checks IP Address reputation

        :return: list of dicts in request result
        """
        data = {"host": self.ip}
        url = f"{self.api_url}/search/terms"
        response = self._api_post(url=url, data=data)
        sorted_result = self._sort_results(result=response.json().get("result"))

        return sorted_result

    def check_hash(self) -> Union[List[Dict], None]:
        """Checks File Hash reputation

        :return: list of dicts in request result
        """
        data = {"hash": self.file_hash}
        url = f"{self.api_url}/search/hash"
        response = self._api_post(url=url, data=data)
        sorted_result = self._sort_results(result=response.json())

        return sorted_result

    def check_url(self) -> Union[List[Dict], None]:
        """Checks URL reputation

        :return: list of dicts in request result
        """
        data = {"url": self.url}
        url = f"{self.api_url}/search/terms"
        response = self._api_post(url=url, data=data)
        sorted_result = self._sort_results(result=response.json().get("result"))

        return sorted_result

    def check_report(self, sandbox_report: Optional[str] = "summary") -> Dict:
        """Checks for summary of a submission

        :param sandbox_report: default summary (see https://www.hybrid-analysis.com/docs/api/v2/)
        :return: dict of request response
        """
        url = f"{self.api_url}/report/{self.job_id}/{sandbox_report}"
        response = self._api_get(url=url)

        return response.json()
