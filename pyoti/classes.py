class API:
    """Base API for PyOTI"""

    def __init__(self, api_key: str = None, api_url: str = None):
        """
        :param api_key: API key for the endpoint to connect to
        :param api_url: URL of the API endpoint to connect to
        """
        self._api_key = api_key
        self._api_url = api_url

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, value):
        self._api_key = value

    @property
    def api_url(self):
        return self._api_url

    @api_url.setter
    def api_url(self, value):
        self._api_url = value


class Domain(API):
    """Domain API for PyOTI"""

    def __init__(self, api_key: str = None, api_url: str = None, domain: str = None):
        """
        :param api_key: API key for the endpoint to connect to
        :param api_url: URL of the API endpoint to connect to
        :param domain:  domain to check/scan
        """
        self._domain = domain
        API.__init__(self, api_key, api_url)

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, value):
        self._domain = value


class FileHash(API):
    """FileHash API for PyOTI"""

    def __init__(self, api_key: str = None, api_url: str = None, file_hash: str = None):
        """
        :param api_key: API key for the endpoint to connect to
        :param api_url: URL of the API endpoint to connect to
        :param file_hash: file hash to check/scan
        """
        self._file_hash = file_hash
        API.__init__(self, api_key, api_url)

    @property
    def file_hash(self):
        return self._file_hash

    @file_hash.setter
    def file_hash(self, value):
        self._file_hash = value


class IPAddress(API):
    """IPAddress API for PyOTI"""

    def __init__(self, api_key: str = None, api_url: str = None, ip: str = None):
        """
        :param api_key: API key for the endpoint to connect to
        :param api_url: URL of the API endpoint to connect to
        :param ip: IP address to check/scan
        """
        self._ip = ip
        API.__init__(self, api_key, api_url)

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, value):
        self._ip = value


class URL(API):
    """URL API for PyOTI"""

    def __init__(self, api_key: str = None, api_url: str = None, url: str = None):
        """
        :param api_key: API key for the endpoint to connect to
        :param api_url: URL of the API endpoint to connect to
        :param url: URL to scan/check
        """
        self._url = url
        API.__init__(self, api_key, api_url)

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        self._url = value


class EmailAddress(API):
    """EmailAddress API for PyOTI"""

    def __init__(self, api_key: str = None, api_url: str = None, email: str = None):
        """
        :param api_key: API key for the endpoint to connect to
        :param api_url: URL of the API endpoint to connect to
        :param email: URL to scan/check
        """
        self._email = email
        API.__init__(self, api_key, api_url)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        self._email = value
