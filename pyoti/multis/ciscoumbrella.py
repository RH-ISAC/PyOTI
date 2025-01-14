import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, List, Optional, Union

from pyoti import __version__
from pyoti.classes import Domain, IPAddress


class CiscoUmbrellaInvestigate(Domain, IPAddress):
    """
    CiscoUmbrellaInvestigate

    Cisco Umbrella Investigate provides detection, scoring, and prediction of emerging threats. You can predict the
    likelihood that a domain, an IP address, or entire ASN may contribute to the origin of an attack or pose a security
    threat before an attack or threat occurs. Umbrella Investigate is based on domain information gathered by the
    Umbrella Global Network.
    """
    def __init__(
            self,
            api_key: str,
            api_url: str = "https://api.umbrella.com/investigate/v2",
            api_token: Optional[str] = None
    ):
        """
        :param api_key: CiscoUmbrellaInvestigate API key
        :param api_url: CiscoUmbrellaInvestigate base API URL
        """
        self._api_token = api_token
        Domain.__init__(self, api_url=api_url, api_key=api_key)
        IPAddress.__init__(self, api_url=api_url, api_key=api_key)

    @property
    def api_token(self):
        return self._api_token

    @api_token.setter
    def api_token(self, value):
        self._api_token = value

    def _api_post(self, url: str, data: Union[Dict, str], auth: Optional[HTTPBasicAuth] = None) -> requests.models.Response:
        """POST request to API"""
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': f"PyOTI {__version__}"
        }

        if not auth and self.api_token:
            headers['Authorization'] = f"Bearer {self.api_token}"

        response = requests.request("POST", url=url, data=data, headers=headers, auth=auth)

        return response

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API"""
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': f"PyOTI {__version__}"
        }
        if self.api_token:
            headers['Authorization'] = f"Bearer {self._api_token}"

        response = requests.request("GET", url=url, headers=headers)

        return response

    def _get_token(self) -> None:
        """Get OAuth API token"""
        client_id = self.api_key.split(":")[0]
        client_secret = self.api_key.split(":")[1]

        data = {'grant_type': 'client_credentials'}
        auth = HTTPBasicAuth(client_id, client_secret)
        self.api_token = self._api_post(
            url="https://api.umbrella.com/auth/v2/token",
            data=data,
            auth=auth
        ).json().get('access_token')

    def check_domain_status_and_categorization(self, show_labels: bool = True) -> Union[Dict, None]:
        """
        Check domain status and categorization

        Look up the status and security and content category IDs for a domain.

        The domain status is a numerical value determined by the Cisco Security Labs team.
        Valid status values are: '-1' (malicious), '1' (safe), or '0' (undetermined status).

        :param show_labels: display the security and content category labels in the response
        """
        if not self.api_token:
            self._get_token()

        if show_labels:
            url = f"{self.api_url}/domains/categorization/{self.domain}?showLabels"
        else:
            url = f"{self.api_url}/domains/categorization/{self.domain}"
        response = self._api_get(url=url)

        return response.json()

    def bulk_check_domain_status_and_categorization(
            self,
            domains: List[str],
            show_labels: bool = True
    ) -> Union[List[Dict], None]:
        """
        Bulk check domain status and categorization

        Provide a list of domains and look up the status, and security and content category IDs for each domain.

        In a single request, the payload must not exceed 100KB and contain no more than 1000 domains.

        :param domains: list of domains to check status and categorization
        :param show_labels: display the security and content category labels in the response
        """
        if not self.api_token:
            self._get_token()

        payload = f'''{domains}'''

        if show_labels:
            url = f"{self.api_url}/domains/categorization?showLabels"
        else:
            url = f"{self.api_url}/domains/categorization"
        response = self._api_post(url=url, data=payload)

        return response.json()

    def check_domain_security_score(self) -> Union[Dict, None]:
        """
        Check domain security score information

        List multiple scores or security features for a domain. You can use the scores or security features to determine
        relevant data points and build insights on the reputation or security risk posed by the site. No one security
        information feature is conclusive. Instead, consider these features as part of your security research.
        """
        if not self.api_token:
            self._get_token()

        url = f"{self.api_url}/security/name/{self.domain}"

        response = self._api_get(url=url)

        return response.json()

    def check_domain_risk_score(self) -> Union[Dict, None]:
        """
        Check domain risk score

        The Investigate Risk Score is based on an analysis of the lexical characteristics of the domain name and
        patterns in queries and requests to the domain. The risk score is scaled from 0 to 100 where 100 is the highest
        risk and 0 represents no risk at all. Periodically, Investigate updates this score based on additional inputs.
        A domain blocked by Umbrella receives a score of 100.
        """
        if not self.api_token:
            self._get_token()

        url = f"{self.api_url}/domains/risk-score/{self.domain}"

        response = self._api_get(url=url)

        return response.json()

    def check_ip_resource_records(self) -> Union[Dict, None]:
        """
        Check IP resource records

        Get the Resource Record (RR) data for DNS responses, and categorization data, where the answer (or rdata) is
        the domain(s).
        """
        if not self.api_token:
            self._get_token()

        url = f"{self.api_url}/pdns/ip/{self.ip}"

        response = self._api_get(url=url)

        return response.json()