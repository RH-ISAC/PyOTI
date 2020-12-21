import json
import re
import xmltodict

from datetime import datetime, timedelta
from shutil import which

from pyoti.exceptions import PyOTIError

HASH_TYPE = {
    re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE):  "MD5",
    re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE):  "SHA-1",
    re.compile(r"^[a-f0-9]{64}(:.+)?$", re.IGNORECASE):  "SHA-256",
    re.compile(r"^[a-f0-9]{128}(:.+)?$", re.IGNORECASE): "SHA-512",
}

def get_hash_type(file_hash):
    """Determines File Hash type"""

    for regex, algorithm in HASH_TYPE.items():
        if regex.match(file_hash):

            return algorithm

def pypkg_exists(pypkg):
    """Checks if python package is installed"""

    if not which(pypkg):
        raise PyOTIError(f"{pypkg} not installed!")

def time_since_epoch(epoch):
    return datetime.fromtimestamp(int(epoch)).strftime('%Y-%m-%d %H:%M:%S')

def time_since_seconds(seconds):
    return str(timedelta(seconds=seconds))

def xml_to_json(xml_object):
    """Convert XML to JSON"""

    xml_dict = xmltodict.parse(xml_object)
    json_data = json.dumps(xml_dict)
    return json_data
