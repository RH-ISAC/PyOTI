import base64
import os
import requests
import time
from typing import Dict, Optional

from pyoti import __version__
from pyoti.classes import Domain, FileHash, IPAddress, URL
from pyoti.exceptions import VirusTotalError


class VirusTotalV2(Domain, FileHash, IPAddress, URL):
    """VirusTotal IOC Analyzer

    VirusTotal analyzes files and URLs enabling detection of malicious content
    using antivirus engines and website scanners. (VT API v2)
    """
    def __init__(
        self, api_key: str, api_url: str = "https://www.virustotal.com/vtapi/v2"
    ):
        """
        :param api_key: VirusTotal API key
        :param api_url: VirusTotal v2 base API URL
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, endpoint: str, ioctype: str, iocvalue: str, allinfo: Optional[bool], scan: Optional[bool] = None) -> requests.models.Response:
        """GET request to API

        :param endpoint: VirusTotal v2 API endpoint
        :param ioctype: domain, resource, or ip
        :param iocvalue: domain, filehash, ip address, URL
        :param allinfo: more details with VT premium
        :param scan: submit URL for analysis if no report is found
        """
        headers = {"User-Agent": f"PyOTI {__version__}"}

        params = {"apikey": self.api_key, ioctype: iocvalue}
        if allinfo:
            params["allinfo"] = True
        if scan:
            params["scan"] = 1

        response = requests.request("GET", url=endpoint, headers=headers, params=params)

        return response

    def check_domain(self, allinfo: bool = False) -> Dict:
        """Checks Domain reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :return: dict of request response
        """
        url = f"{self.api_url}/domain/report"
        response = self._api_get(url, "domain", self.domain, allinfo)

        return response.json()

    def check_hash(self, allinfo: bool = False, scan_id: str = None) -> Dict:
        """Checks File Hash Reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup by scan_id (returned by the /file/scan endpoint).
        :return: dict of request response
        """
        url = f"{self.api_url}/file/report"
        if self.file_hash:
            response = self._api_get(url, "resource", self.file_hash, allinfo)
        elif not self.file_hash and scan_id:
            response = self._api_get(url, "resource", scan_id, allinfo)
        else:
            raise VirusTotalError(
                "/file/report endpoint requires a valid MD5/SHA1/SHA256 hash or scan_id!"
            )

        return response.json()

    def check_ip(self, allinfo: bool = False) -> Dict:
        """Checks IP reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :return: dict of request response
        """
        url = f"{self.api_url}/ip-address/report"
        response = self._api_get(url, "ip", self.ip, allinfo)

        return response.json()

    def check_url(self, allinfo: bool = False, scan_id: str = None, scan: bool = None) -> Dict:
        """Checks URL reputation

        :param allinfo: Default: False. Set True if you have VirusTotal Premium API Key
        :param scan_id: Default: None. Set if you want to lookup by scan_id (returned by the /url/scan endpoint).
        :param scan: Default: None. Set True to submit URL for analysis if no report is found in VT database.
        :return: dict of request response
        """
        url = f"{self.api_url}/url/report"
        if self.url:
            response = self._api_get(url, "resource", self.url, allinfo, scan)
        elif not self.url and scan_id:
            response = self._api_get(url, "resource", scan_id, allinfo, scan)
        elif self.url and not scan_id and scan:
            response = self._api_get(url, "resource", scan_id, allinfo, scan)
            sid = response["scan_id"]
            # sleep 5 seconds while VT scans URL before querying for results
            time.sleep(5)
            response = self._api_get(url, "resource", sid, allinfo, scan)
        else:
            raise VirusTotalError(
                "/url/report endpoint requires a valid URL or scan_id!"
            )

        return response.json()


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
