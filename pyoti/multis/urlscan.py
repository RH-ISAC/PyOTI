import json
import requests
import time
from typing import Dict, Optional
from uuid import UUID

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import PyOTIError


class URLscan(Domain, FileHash, IPAddress, URL):
    """URLscan a sandbox for the web

    URLscan is a free service to scan and analyse websites.
    """
    def __init__(self, api_key: str, api_url: str = "https://urlscan.io/api/v1", id=None):
        self._id = id
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self,  api_key=api_key, api_url=api_url)
        IPAddress.__init__(self,  api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

        self.countries = [
            "de",
            "us",
            "jp",
            "fr",
            "gb",
            "nl",
            "ca",
            "it",
            "es",
            "se",
            "fi",
            "dk",
            "no",
            "is",
            "au",
            "nz",
            "pl",
            "sg",
            "ge",
            "pt",
            "at",
            "ch"
        ]

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    def _api_get(self, endpoint: str, params: Optional[Dict]) -> requests.models.Response:
        """GET request to urlscan API

        :param endpoint: urlscan API endpoint
        :param params: params for request
        """
        headers = {
            "API-Key": self.api_key,
            "User-Agent": f"PyOTI {__version__}"
        }
        rparams = params

        uri = self.api_url + endpoint
        response = requests.request("GET", url=uri, headers=headers, params=rparams)

        return response

    def _api_post(self, endpoint: str, data: Optional[Dict]) -> requests.models.Response:
        """POST request to urlscan API"""
        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": f"PyOTI {__version__}"
        }
        response = requests.request("POST", url=endpoint, headers=headers, data=json.dumps(data))

        return response

    def _escape_url(self, url: str) -> str:
        """Escape URL for elastic syntax

        :param url: url to escape
        :return: escaped url for elastic syntax
        """
        url = url.replace(":", "\:")
        url = url.replace("/", "\/")

        return url

    def search_domain(self, contacted: bool = False, limit: int = 100) -> Dict:
        """
        :param contacted: default False (domain was contacted but isn't the page/primary domain)
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        if contacted:
            params = {"q": f"domain:{self.domain} AND NOT page.domain:{self.domain}", "size": limit}
        else:
            params = {"q": f"domain:{self.domain}", "size": limit}

        response = self._api_get(endpoint="/search/", params=params)

        return response.json()

    def search_hash(self, limit: int = 100) -> Dict:
        """
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        params = {"q": f"hash:{self.file_hash}", "size": limit}

        response = self._api_get(endpoint="/search/", params=params)

        return response.json()

    def search_ip(self, limit: int = 100) -> Dict:
        """
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        params = {"q": f"page.ip:{self.ip}", "size": limit}

        response = self._api_get(endpoint="/search/", params=params)

        return response.json()

    def search_url(self, limit: int = 100) -> Dict:
        """
        :param limit: default 100 (number of results to return, max: 10000)
        :return: dict of request response
        """
        params = {"q": f"task.url:{self._escape_url(self.url)}", "size": limit}

        response = self._api_get(endpoint="/search/", params=params)

        return response.json()

    def check_domain(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            response = self._api_get(endpoint=f"/result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_domain method to get result UUID.")

        return response.json()

    def check_hash(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            response = self._api_get(endpoint=f"/result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_hash method to get result UUID.")

        return response.json()

    def check_ip(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            response = self._api_get(endpoint=f"/result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_ip method to get result UUID.")

        return response.json()

    def check_url(self, uuid: UUID = None) -> Dict:
        """
        :param uuid: urlscan result UUID
        :return: dict of request response
        """
        if uuid:
            response = self._api_get(endpoint=f"/result/{uuid}", params=None)
        else:
            raise PyOTIError("Missing result UUID. Use search_url method to get result UUID.")

        return response.json()

    def submit_url(
            self,
            user_agent: Optional[str],
            referer: Optional[str],
            visibility: Optional[str],
            country: Optional[str]
    ) -> Dict:
        """Submit a URL to be scanned and set some options for the scan

        :param user_agent: Override User-Agent for this scan
        :param referer: Override HTTP referer for this scan
        :param visibility: One of [public, unlisted, private]. Defaults to your URLscan account configured default visibility
        :param country: Specify which country the scan should be performed from (2-letter ISO-3166-1 alpha-2 country)
        """
        data = {"url": self.url}
        if user_agent:
            data["customagent"] = user_agent
        if referer:
            data["referer"] = referer
        if visibility:
            data["visibility"] = visibility
        if country:
            if country.lower() in self.countries:
                data["country"] = country
            else:
                raise Exception(
                    f"[!] {country} is not a valid entry. Please choose from the following list: {self.countries}"
                )

        response = self._api_post(endpoint=f"{self.api_url}/scan", data=data)

        return response.json()

    def get_submission_results(self, uuid: UUID) -> Dict:
        start_time = time.time()
        timeout = 180  # seconds

        while True:
            elapsed_time = time.time() - start_time

            if elapsed_time > timeout:
                # upper timeout reached
                raise TimeoutError(f"Timeout reached while waiting on submission results for UUID: {uuid}")

            response = self._api_get(endpoint=f"/result/{uuid}/", params=None)
            if response.status_code == 404:
                time.sleep(5)
            elif response.status_code == 200:
                return response.json()
