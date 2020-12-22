import pydig

from pyoti.classes import FileHash
from pyoti.utils import time_since_epoch


class MalwareHashRegistry(FileHash):
    """MalwareHashRegistry Malicious File Hashes

    Team Cymru aggregates results of over 30 AV tools, including their own analysis,
    to improve detection rates of malicious files.
    """

    def check_hash(self):
        """Checks file hash reputation

        Checks Team Cymru's Malware Hash Registry for time last seen and
        detection percentage of a given file hash.
        """

        dig = pydig.query(f"{self.file_hash}.malware.hash.cymru.com", "TXT")
        if dig:
            return_list = self._to_list(dig)

            return self._to_dict(return_list)

    def _to_list(self, value):
        """Converts dig query to list"""

        strip = value[0].strip('"')
        split = strip.split(" ")

        return split

    def _to_dict(self, value):
        """Converts dig query list to dict"""

        result = {}
        epoch = value[0]
        human = time_since_epoch(epoch)
        result['last_seen'] = human
        result['detection_pct'] = value[1]

        return result
