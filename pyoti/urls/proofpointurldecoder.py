import base64
import re
import string
from html import unescape
from urllib.parse import unquote

from pyoti.classes import URL


class ProofpointURLDecoder(URL):
    """Decode URLs rewritten by Proofpoint URL Defense. Supports v1, v2, and v3 URLs.

    Adopted from the script originally authored by Eric Van Cleve:
    https://help.proofpoint.com/@api/deki/files/177/URLDefenseDecode.py?revision=3
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
        URL.__init__(self)

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
