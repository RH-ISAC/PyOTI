import pydig

from pyoti.classes import FileHash
from pyoti.utils import time_since_epoch


class MalwareHashRegistry(FileHash):
    def check_hash(self):
        dig = pydig.query(f"{self.file_hash}.malware.hash.cymru.com", "TXT")
        if dig:
            return_list = self._to_list(dig)

            return self._to_json(return_list)

    def _to_list(self, value):
        strip = value[0].strip('"')
        split = strip.split(" ")

        return split

    def _to_json(self, value):
        result = {}
        epoch = value[0]
        human = time_since_epoch(epoch)
        result['last_seen'] = human
        result['detection_pct'] = value[1]

        return result
