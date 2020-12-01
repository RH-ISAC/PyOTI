import base64
import json
import requests

from pyoti.classes import URL
from pyoti.exceptions import GSBPermissionDenied, GSBInvalidAPIKey
from pyoti.utils import xml_to_json


class Phishtank(URL):
    def __init__(self, api_key=None, api_url="http://checkurl.phishtank.com/checkurl/", url=None, username=None):
        self._username = username
        URL.__init__(self, api_key, api_url, url)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    def check_url(self):
        new_check_bytes = self.url.encode('ascii')
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        self._api_url += base64_new_check
        headers = {
            'app_key': self._api_key,
            'User-agent': f"phishtank/{self._username}"
        }

        response = requests.request("POST", url=self._api_url, headers=headers)

        return xml_to_json(response.text)


class GoogleSafeBrowsing(URL):
    def __init__(self, url=None, api_key=None, api_url='https://safebrowsing.googleapis.com/v4/threatMatches:find'):
        self.api_url = api_url
        URL.__init__(self, api_key, api_url, url)

    def check_url(self, platforms=["ANY_PLATFORM"]):
        data = {
            "client": {
                "clientId": "PyOTI",
                "clientVersion": "0.1"
            },
            "threatInfo": {
                "threatTypes":
                    [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "THREAT_TYPE_UNSPECIFIED",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                        "UNWANTED_SOFTWARE"
                    ],
                "platformTypes": platforms,
                "threatEntryTypes": ["URL"],
                "threatEntries": [{'url': self._url}]
            }
        }

        headers = {'Content-type': 'application/json'}

        response = requests.request("POST",
                                    url=self.api_url,
                                    data=json.dumps(data),
                                    params={'key': self._api_key},
                                    headers=headers)

        if response.status_code == 200:
            if response.json() == {}:
                return "No matches!"
            else:
                return response.json()

        elif response.status_code == 400:
            raise GSBInvalidAPIKey(response.json()['error']['message'])

        elif response.status_code == 403:
            raise GSBPermissionDenied(response.json()['error']['message'])
