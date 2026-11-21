import requests
from typing import Dict, Optional, Union

from pyoti import __version__
from pyoti.classes import Domain, IPAddress, URL


class NetAPI(Domain, IPAddress, URL):
    """NetAPI Compromised Domain and IP Feeds

    NetAPI publishes a compromised IP feed (addresses caught attacking its own honeypot network, rebuilt every hour)
    and a compromised domain feed (phishing and malware domains, updated daily), both free under CC BY 4.0. The API
    works without a key; a free API token raises the request limits.
    """
    def __init__(self, api_key: Optional[str] = None, api_url: str = "https://netapi.com/api-json/"):
        """
        :param api_key: NetAPI API token (optional)
        :param api_url: NetAPI JSON API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, params: Dict) -> requests.models.Response:
        """GET request to API"""
        headers = {"User-Agent": f"PyOTI {__version__}"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        response = requests.request("GET", url=self.api_url, headers=headers, params=params)

        return response

    def _query(self, params: Dict) -> Union[Dict, str]:
        """Runs an API method

        :param params: API method and its parameters
        :return: dict of request response, or the error message
        """
        response = self._api_get(params)

        try:
            data = response.json()
        except ValueError:
            return f"HTTP {response.status_code}"

        if response.status_code == 200:
            return data

        return data.get("error", {}).get("message", f"HTTP {response.status_code}")

    def _check_compromised(self, ioc: str) -> Union[Dict, str]:
        """Checks the compromised feeds

        :param ioc: domain, hostname, url or ip address
        :return: dict of request response
        """
        return self._query({"method": "compromised-check", "value": ioc})

    def check_domain(self) -> Union[Dict, str]:
        """Checks Domain against the compromised domain feed

        A hostname is also matched through its parent domains (matched_value).

        :return: dict of request response
        """
        return self._check_compromised(self.domain)

    def check_ip(self) -> Union[Dict, str]:
        """Checks IP against the compromised IP feed

        listed_now: the address attacked in the last 48 hours, listed_ever: in the last 30 days.

        :return: dict of request response
        """
        return self._check_compromised(self.ip)

    def check_url(self) -> Union[Dict, str]:
        """Checks the host of a URL against the compromised feeds

        :return: dict of request response
        """
        return self._check_compromised(self.url)

    def check_domain_rank(self) -> Union[Dict, str]:
        """Checks Domain rank in the NetAPI Top 1M most popular websites

        :return: dict of request response
        """
        return self._query({"method": "domain-rank", "domain": self.domain})
