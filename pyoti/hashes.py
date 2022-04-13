import pydig
from typing import Dict, List

from pyoti.classes import FileHash
from pyoti.utils import get_hash_type, time_since_epoch


class MalwareHashRegistry(FileHash):
    """MalwareHashRegistry Malicious File Hashes

    Team Cymru aggregates results of over 30 AV tools, including their own analysis,
    to improve detection rates of malicious files.
    """
    def check_hash(self) -> Dict:
        """Checks file hash reputation

        Checks Team Cymru's Malware Hash Registry for time last seen and
        detection percentage of a given file hash.

        :return: query results with last seen date and detection percentage
        """
        if get_hash_type(self.file_hash) == "MD5" or "SHA-1":
            dig = pydig.query(f"{self.file_hash}.malware.hash.cymru.com", "TXT")
            if dig:
                return_list = self._to_list(dig)

                return self._to_dict(return_list)

    def _to_list(self, value: List[str]) -> List[str]:
        """Converts dig query to list

        pydig returns a list with values contained as a single element and needs to be split

        :param value: pydig query result
        :return: a list with the values split into separate elements
        """
        strip = value[0].strip('"')
        split = strip.split(" ")

        return split

    def _to_dict(self, value: List[str]) -> Dict[str, str]:
        """Converts dig query list to dict

        :return: dict
        """
        result = {}
        epoch = value[0]
        human = time_since_epoch(epoch)
        result["last_seen"] = human
        result["detection_pct"] = value[1]

        return result
