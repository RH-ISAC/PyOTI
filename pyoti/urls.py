import base64
import json
import re
import requests
import string
import sys

from html import unescape
from urllib.parse import unquote, urlencode

from pyoti.classes import URL
from pyoti.exceptions import GSBError, LinkPreviewError
from pyoti.utils import xml_to_json


class GoogleSafeBrowsing(URL):
    """GoogleSafeBrowsing URL Blacklist

    Google Safe Browsing is a blacklist service provided by Google that
    provides lists of URLs for web resources that contain malware or phishing
    content.
    """

    def __init__(
        self,
        api_key,
        api_url="https://safebrowsing.googleapis.com/v4/threatMatches:find",
    ):
        URL.__init__(self, api_key, api_url)

    def _api_post(self, endpoint, platforms):
        """POST request to API"""

        error_code = [400, 403, 429, 500, 503, 504]

        data = {
            "client": {"clientId": "PyOTI", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "THREAT_TYPE_UNSPECIFIED",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": platforms,
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": self.url}],
            },
        }

        headers = {"Content-type": "application/json", "Accept-Encoding": "gzip"}

        response = requests.request(
            "POST",
            url=endpoint,
            json=data,
            params={"key": self.api_key},
            headers=headers,
        )

        if response.status_code == 200:
            if response.json() == {}:
                r = {}
                r['matches'] = []
                return r
            else:
                return response.json()

        elif response.status_code in error_code:
            raise GSBError(response.json()["error"]["message"])

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

    def __init__(self, api_key, api_url="https://api.linkpreview.net"):
        URL.__init__(self, api_key, api_url)

    def _api_get(self):
        """GET request to API"""

        error_code = [400, 401, 403, 404, 423, 425, 426, 429]

        params = {"key": self.api_key, "q": self.url}

        encoded = urlencode(params)

        response = requests.request("GET", url=self.api_url, params=encoded)

        if response.status_code == 200:
            return response.json()

        elif response.status_code in error_code:
            raise LinkPreviewError(response.json()["description"])

    def check_url(self):
        """Checks URL reputation"""

        response = self._api_get()

        return response


class Phishtank(URL):
    """Phishtank Anti-Phishing

    Phishtank is a collaborative clearing house for data and information about
    phishing on the internet.
    """

    def __init__(
        self,
        api_key,
        api_url="http://checkurl.phishtank.com/checkurl/",
        username="PyOTI",
    ):
        self._username = username
        URL.__init__(self, api_key, api_url)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    def _api_post(self):
        """POST request to API"""

        new_check_bytes = self.url.encode("ascii")
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode("ascii")
        api_uri = self.api_url + base64_new_check
        headers = {"app_key": self.api_key, "User-agent": f"phishtank/{self.username}"}

        response = requests.request("POST", url=api_uri, headers=headers)

        return xml_to_json(response.text)

    def check_url(self):
        """Checks URL reputation"""

        response = self._api_post()

        try:
            return response["response"]["results"]["url0"]
        except KeyError:
            return response["response"]["results"]


class ProofpointURLDecoder(URL):
    """Decode URLs rewritten by Proofpoint URL Defense. Supports v1, v2, and v3 URLs.

    Adopted from the script originally authored by Eric Van Cleve: https://help.proofpoint.com/@api/deki/files/177/URLDefenseDecode.py?revision=3
    """

    def __init__(self):
        self.ud_pattern = re.compile(r'https://urldefense(?:\.proofpoint)?\.com/(v[0-9])/')
        self.v1_pattern = re.compile(r'u=(?P<url>.+?)&k|amp;k=')
        self.v2_pattern = re.compile(r'u=(?P<url>.+?)&[dc]=')
        self.v3_pattern = re.compile(r'v3/__(?P<url>.+?)__;(?P<enc_bytes>.*?)!')
        self.v3_token_pattern = re.compile(r"\*(\*.)?")
        self.v3_run_mapping = {}
        run_values = string.ascii_uppercase + string.ascii_lowercase + string.digits + '-' + '_'
        run_length = 2
        for value in run_values:
            self.v3_run_mapping[value] = run_length
            run_length += 1
        self.maketrans = str.maketrans

    def _decode(self, rewritten_url):
        match = self.ud_pattern.search(rewritten_url)
        if match:
            if match.group(1) == 'v1':
                return self._decode_v1(rewritten_url)
            elif match.group(1) == 'v2':
                return self._decode_v2(rewritten_url)
            elif match.group(1) == 'v3':
                return self._decode_v3(rewritten_url)
            else:
                raise ValueError('Unrecognized version in: ', rewritten_url)
        else:
            raise ValueError('Does not appear to be a URL Defense URL')

    def _decode_v1(self, rewritten_url):
        match = self.v1_pattern.search(rewritten_url)
        if match:
            url_encoded_url = match.group('url')
            html_encoded_url = unquote(url_encoded_url)
            url = unescape(html_encoded_url)
            return url
        else:
            raise ValueError('Error parsing URL')

    def _decode_v2(self, rewritten_url):
        match = self.v2_pattern.search(rewritten_url)
        if match:
            special_encoded_url = match.group('url')
            trans = self.maketrans('-_', '%/')
            url_encoded_url = special_encoded_url.translate(trans)
            html_encoded_url = unquote(url_encoded_url)
            url = unescape(html_encoded_url)
            return url
        else:
            raise ValueError('Error parsing URL')

    def _decode_v3(self, rewritten_url):
        def replace_token(token):
            if token == '*':
                character = self.dec_bytes[self.current_marker]
                self.current_marker += 1
                return character
            if token.startswith('**'):
                run_length = self.v3_run_mapping[token[-1]]
                run = self.dec_bytes[self.current_marker:self.current_marker + run_length]
                self.current_marker += run_length
                return run

        def substitute_tokens(text, start_pos=0):
            match = self.v3_token_pattern.search(text, start_pos)
            if match:
                start = text[start_pos:match.start()]
                built_string = start
                token = text[match.start():match.end()]
                built_string += replace_token(token)
                built_string += substitute_tokens(text, match.end())
                return built_string
            else:
                return text[start_pos:len(text)]

        match = self.v3_pattern.search(rewritten_url)
        if match:
            url = match.group('url')
            encoded_url = unquote(url)
            enc_bytes = match.group('enc_bytes')
            enc_bytes += '=='
            self.dec_bytes = (base64.urlsafe_b64decode(enc_bytes)).decode('utf-8')
            self.current_marker = 0
            return substitute_tokens(encoded_url)
        else:
            raise ValueError('Error parsing URL')

    def check_url(self):
        return self._decode(self.url)