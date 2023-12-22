import base64
import os
import requests
import time
from typing import Dict

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL


class VirusTotalV3(Domain, FileHash, IPAddress, URL):
    """VirusTotal IOC Analyzer

    VirusTotal analyzes files and URLs enabling detection of malicious content
    using antivirus engines and website scanners. (VT API v3)
    """
    def __init__(
        self, api_key, api_url="https://www.virustotal.com/api/v3"
    ):
        """
        :param api_key: VirusTotal API key
        :param api_url: VirusTotal v3 base API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str) -> requests.models.Response:
        """GET request to API

        :param url: VirusTotal API endpoint URL
        """
        headers = {
            "x-apikey": self.api_key,
            "User-Agent": f"PyOTI {__version__}"
        }

        response = requests.request("GET", url=url, headers=headers)

        return response

    def _api_post(self, url: str, file_path: str, zip_pw: str = None) -> requests.models.Response:
        """POST request to API
        :param url: VirusTotal API endpoint URL
        :param file_path: Path for file to submit
        :param zip_pw: Password if ZIP file submission
        """
        headers = {
            "x-apikey": self.api_key,
            "User-Agent": f"PyOTI {__version__}",
            "Accept": "application/json",
        }

        files = {
            "file": (
                os.path.basename(file_path),
                open(os.path.abspath(file_path), "rb")
            )
        }

        if zip_pw is not None:
            payload = {"password": zip_pw}
            response = requests.request("POST", url=url, files=files, headers=headers, data=payload)
        else:
            response = requests.request("POST", url=url, files=files, headers=headers)

        return response

    def check_domain(self) -> Dict:
        """Retrieve information about an Internet domain

        :return: dict of request response
        """
        url = f"{self.api_url}/domains/{self.domain}"
        response = self._api_get(url=url)

        return response.json()

    def check_hash(self) -> Dict:
        """Retrieve information about a file

        :return: dict of request response
        """
        url = f"{self.api_url}/files/{self.file_hash}"
        response = self._api_get(url=url)

        return response.json()

    def check_ip(self) -> Dict:
        """Retrieve information about an IP address

        :return: dict of request response
        """
        url = f"{self.api_url}/ip_addresses/{self.ip}"
        response = self._api_get(url=url)

        return response.json()

    def check_url(self) -> Dict:
        """Retrieve information about a URL

        :return: dict of request response
        """
        url_id = base64.urlsafe_b64encode(self.url.encode()).decode().strip("=")
        url = f"{self.api_url}/urls/{url_id}"
        response = self._api_get(url=url)

        return response.json()

    def upload_file(self, file_path: str, zip_pw: str = None) -> Dict:
        """Upload and analyse a file

        :param file_path: Path for file to submit
        :param zip_pw: Password if ZIP file submission
        """
        # TODO: file size checks
        #  - this endpoint allows <= 32mb
        #  - /files/upload_url allows 32mb >= FILE <= 650mb
        #  add a timeout to the while loop so we don't sit here infinitely
        url = f"{self.api_url}/files"
        response = self._api_post(url=url, file_path=file_path, zip_pw=zip_pw)
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"{self.api_url}/analyses/{analysis_id}"
        print("[+] File queued for analysis!")
        while self._api_get(url=analysis_url).json()["data"]["attributes"]["status"] == "queued":
            time.sleep(5)
        analysis_resp = self._api_get(url=f"{self.api_url}/analyses/{analysis_id}")
        link = f"https://virustotal.com/gui/file/{analysis_resp.json()['meta']['file_info']['sha256']}"
        print(f"[!] File analysis completed! VT Sample Link: {link}")

        return analysis_resp.json()
