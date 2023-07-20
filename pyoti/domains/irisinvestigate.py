import hmac
import hashlib
import requests
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlsplit

from pyoti import __version__
from pyoti.classes import Domain


class IrisInvestigate(Domain):
    """IrisInvestigate Domain Risk Score/Historical DNS Records/SSL Profiles

    Iris is a proprietary threat intelligence/investigation platform by Domaintools
    """
    def __init__(self, api_key: str, api_url: str = "https://api.domaintools.com/v1/iris-investigate/"):
        """
        :param api_key: Domaintools API key in 'USER:SECRET' format
        :param api_url: Domaintools API url
        """
        Domain.__init__(self, api_key, api_url)

    def _api_post(self, **kwargs) -> requests.models.Response:
        """POST request to Iris Investigate API

        :return: dict of request response
        """
        creds = self.api_key.split(":")
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        param = ''.join([creds[0], timestamp, urlsplit(self.api_url).path])
        signature = hmac.new(creds[1].encode('utf-8'), param.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {
            'api_username': creds[0],
            'signature': signature,
            'timestamp': timestamp,
        }

        if kwargs.get('domain_list'):
            params['domain'] = ','.join(kwargs.get('domain_list'))

        else:
            params['domain'] = self.domain

        response = requests.request("POST", url=self.api_url, headers=headers, params=params)

        return response

    def check_domain(self) -> List[Dict]:
        """Checks domain reputation

        :return: list of dict containing results from request response
        """
        response = self._api_post()
        r = response.json().get('response')

        return r.get('results')

    def bulk_check_domain(self, domain_list: List[str]) -> List[Dict]:
        """Bulk check domain reputation

        :param domain_list: List of domains to check reputation
        :return: list of dicts containing results from request response
        """
        if len(domain_list) <= 100:
            response = self._api_post(domain_list=domain_list)
            r = response.json().get('response')

            return r.get('results')
        else:
            chunk_size = 100
            chunks = [domain_list[i:i + chunk_size] for i in range(0, len(domain_list), chunk_size)]
            results = []

            for chunk in chunks:
                response = self._api_post(domain_list=chunk)
                r = response.json().get('response')
                [results.append(result) for result in r.get('results')]

                return results
