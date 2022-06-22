import requests
from typing import Dict

from pyoti import __version__
from pyoti.classes import EmailAddress


class EmailRepIO(EmailAddress):
    """EmailRepIO Email Address Reputation

    EmailRep is a system of crawlers, scanners, and enrichment services that
    collects data on email addresses, domains, and internet personas. EmailRep uses
    hundreds of data points from social media profiles, professional networking
    sites, dark web credential leaks, data breaches, phishing kits, phishing emails,
    spam lists, open mail relays, domain age and reputation, deliverability, and
    more to predict the risk of an email address.
    """
    def __init__(self, api_key: str, api_url: str = "https://emailrep.io"):
        """
        :param api_key: EmailRepIO API key
        :param api_url: EmailRepIO base API URL
        """
        EmailAddress.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self) -> requests.models.Response:
        """GET request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "Key": self.api_key
        }

        response = requests.request("GET", url=f"{self.api_url}/{self.email}", headers=headers)

        return response

    def check_email(self) -> Dict:
        """Checks Email Address reputation

        :return: request response dict
        """
        response = self._api_get()

        r = response.json()
        r['remaining_daily_quota'] = response.headers.get('X-Rate-Limit-Daily-Remaining')
        r['remaining_monthly_quota'] = response.headers.get('X-Rate-Limit-Monthly-Remaining')

        return r
