import base64
import json
import requests

from urllib.parse import urlencode

from pyoti.classes import URL
from pyoti.exceptions import GSBPermissionDenied, GSBInvalidAPIKey, LinkPreviewError
from pyoti.keys import googlesafebrowsing, linkpreview, phishtank
from pyoti.utils import xml_to_json


class GoogleSafeBrowsing(URL):
    """GoogleSafeBrowsing URL Blacklist

    Google Safe Browsing is a blacklist service provided by Google that
    provides lists of URLs for web resources that contain malware or phishing
    content.
    """

    def __init__(self, api_key=googlesafebrowsing, api_url='https://safebrowsing.googleapis.com/v4/threatMatches:find'):
        URL.__init__(self, api_key, api_url)

    def _api_post(self, endpoint, platforms):
        """POST request to API"""

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
                "threatEntries": [{'url': self.url}]
            }
        }

        headers = {'Content-type': 'application/json'}

        response = requests.request("POST",
                                    url=endpoint,
                                    data=json.dumps(data),
                                    params={'key': self.api_key},
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

    def check_url(self, platforms=["ANY_PLATFORM"]):
        """Checks URL reputation

        :param platforms: Default: ANY_PLATFORM. For all available options please see:
        https://developers.google.com/safe-browsing/v4/reference/rest/v4/PlatformType
        """

        response = self._api_post(self.api_url, platforms)

        return response


class LinkPreview(URL):
    """LinkPreview Shortened URL Previewer

    LinkPreview API provides basic website information from any given URL.
    """

    def __init__(self, api_key=linkpreview, api_url="https://api.linkpreview.net"):
        URL.__init__(self, api_key, api_url)

    def _api_get(self):
        """GET request to API"""

        error_code = [400, 401, 403, 404, 423, 425, 426, 429]

        params = {
            'key': self.api_key,
            'q': self.url
        }

        encoded = urlencode(params)

        response = requests.request("GET", url=self.api_url, params=encoded)

        if response.status_code == 200:
            return response.json()

        elif response.status_code in error_code:
            raise LinkPreviewError(response.json()['description'])

    def check_url(self):
        """Checks URL reputation"""

        response = self._api_get()

        return response


class Phishtank(URL):
    """Phishtank Anti-Phishing

    Phishtank is a collaborative clearing house for data and information about
    phishing on the internet.
    """

    def __init__(self, api_key=phishtank, api_url="http://checkurl.phishtank.com/checkurl/", username=None):
        self._username = username
        URL.__init__(self, api_key, api_url)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    def _api_post(self, endpoint):
        """POST request to API"""

        new_check_bytes = self.url.encode('ascii')
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        self._api_url += base64_new_check
        headers = {
            'app_key': self.api_key,
            'User-agent': f"phishtank/{self.username}"
        }

        response = requests.request("POST", url=endpoint, headers=headers)

        return xml_to_json(response.text)

    def check_url(self):
        """Checks URL reputation"""

        response = self._api_post(self.api_url)

        return response
