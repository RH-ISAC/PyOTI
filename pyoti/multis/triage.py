import binascii
import json
import os
import requests
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Tuple, Union

from pyoti import __version__
from pyoti.classes import Domain, IPAddress, FileHash, URL


def encode_multipart_formdata(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

    body = BytesIO()
    for field, value in fields.items():  # (name, file)
        if isinstance(value, tuple):
            filename, file = value
            body.write(
                '--{boundary}\r\nContent-Disposition: form-data; '
                'filename="{filename}"; name=\"{field}\"\r\n\r\n'
                .format(boundary=boundary, field=field, filename=filename)
                .encode('utf-8')
            )
            b = file.read()
            if isinstance(b, str):  # If the file was opened in text mode
                b = b.encode('ascii')
            body.write(b)
            body.write(b'\r\n')
        else:
            body.write(
                '--{boundary}\r\nContent-Disposition: form-data;'
                'name="{field}"\r\n\r\n{value}\r\n'
                .format(boundary=boundary, field=field, value=value)
                .encode('utf-8')
            )
    body.write('--{0}--\r\n'.format(boundary).encode('utf-8'))
    body.seek(0)

    return body, "multipart/form-data; boundary=" + boundary


class Triage(Domain, IPAddress, FileHash, URL):
    """
    Triage is Hatching's revolutionary sandboxing solution. It leverages a unique architecture, developed with scaling
    and performance in mind from the start. Triage features Windows, Linux, Android, and macOS analysis capabilities
    and can scale up to 500,000 analyses per day.
    """

    def __init__(self, api_key: str, api_url: str = "https://tria.ge/api/v0"):
        """
        :param api_key: Triage API key
        :param api_url: Triage base API url
        """
        Domain.__init__(self, api_key=api_key, api_url=api_url)
        IPAddress.__init__(self, api_key=api_key, api_url=api_url)
        FileHash.__init__(self, api_key=api_key, api_url=api_url)
        URL.__init__(self, api_key=api_key, api_url=api_url)

    def _api_get(self, url: str, params: Optional[Dict]) -> requests.models.Response:
        """GET request to API"""
        headers = {
            "User-Agent": f"PyOTI {__version__}",
            "Authorization": f"Bearer {self.api_key}"
        }
        response = requests.request("GET", url=url, headers=headers, params=params)

        return response

    def _api_post(
            self,
            endpoint: str,
            submission_type: str,
            data: Optional[Dict] = None,
            file: Optional[Tuple[str, BinaryIO]] = None,
            json_data: Optional[Dict] = None
    ) -> requests.models.Response:
        """POST request to API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"PyOTI {__version__}"
        }
        body = None
        if submission_type == "url":
            headers["Content-Type"] = "application/json"
        elif submission_type == "file":
            body, content_type = encode_multipart_formdata(
                {
                    "_json": json.dumps(data),
                    "file": file
                }
            )
            headers["Content-Type"] = content_type

        response = requests.request(
            "POST",
            url=f"{self.api_url}{endpoint}",
            headers=headers,
            data=body,
            json=json_data
        )

        return response

    def check_domain(self) -> Dict:
        """Check if domain was extracted from C2 data"""
        params = {"query": f"domain:{self.domain}"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def check_hash(self) -> Dict:
        """Check if file hash has been seen by Triage"""
        params = {}
        if len(self.file_hash) == 32:
            params["query"] = f"md5:{self.file_hash}"
        elif len(self.file_hash) == 40:
            params["query"] = f"sha1:{self.file_hash}"
        elif len(self.file_hash) == 64:
            params["query"] = f"sha256:{self.file_hash}"
        else:
            return {"error": "You can only search by MD5, SHA1, or SHA256!"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def check_ip(self) -> Dict:
        """Check if IP address was extracted from C2 data"""
        params = {"query": f"ip:{self.ip}"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def check_url(self) -> Dict:
        """Check if URL was extracted from C2 data"""
        params = {"query": f"url:{self.url}"}
        response = self._api_get(url=f"{self.api_url}/search", params=params)

        return response.json()

    def get_sample_summary(self, sample_id: str) -> Dict:
        """Get the short summary of a sample and its analysis tasks

        :param sample_id: The sample ID to get summary of
        """
        response = self._api_get(url=f"{self.api_url}/samples/{sample_id}/summary", params=None)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {}

    def get_sample_overview(self, sample_id: str) -> Dict:
        """Get the overview of a sample and its analysis tasks. This contains a one-pager with all the high-level
        information related to the sample including malware configuration, signatures, scoring, etc.

        :param sample_id: The sample ID to get summary overview of
        """
        response = self._api_get(url=f"{self.api_url}/samples/{sample_id}/overview.json", params=None)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {}

    def get_sample(self, sample_id: str) -> Dict:
        """Queries the sample with the specified ID

        :param sample_id: The sample ID to query
        """
        response = self._api_get(url=f"{self.api_url}/samples/{sample_id}", params=None)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {}

    def submit_file(self, file_path: Union[str, Path], pw: Optional[str] = None, timeout: Optional[int] = 60,
                    network: Optional[str] = "internet"):
        """Submit a sample file to be analyzed by Triage

        :param file_path: Path to the submission file
        :param pw: Password if file is a ZIP file
        :param timeout: The timeout of analysis (in seconds)
        :param network: The type of network routing to use ("internet"|"drop"|"tor")
        """
        data = {
            "kind": "file",
            "defaults": {
                "timeout": timeout,
                "network": network
            }
        }
        if pw:
            data["password"] = pw

        if not isinstance(file_path, Path):
            file_path = Path(file_path)

        file = (file_path.name, open(file_path, "rb"))

        response = self._api_post(endpoint="/samples", submission_type="file", data=data, file=file)

        return response.json()

    def submit_url(self, timeout: Optional[int] = 60, network: Optional[str] = "internet") -> Dict:
        data = {
            "kind": "url",
            "url": self.url,
            "defaults": {
                "timeout": timeout,
                "network": network
            }
        }

        response = self._api_post(endpoint="/samples", submission_type="url", json_data=data)

        return response.json()

    def fetch_file(self, timeout: Optional[int] = 60, network: Optional[str] = "internet") -> Dict:
        data = {
            "kind": "fetch",
            "url": self.url,
            "defaults": {
                "timeout": timeout,
                "network": network
            }
        }

        response = self._api_post(endpoint="/samples", submission_type="url", json_data=data)

        return response.json()
