class API:
    """Base API for PyOTI

    :param api_key: API key of the endpoint to connect to
    :param api_url: URL of the API endpoint to connect to
    """
    def __init__(self, api_key=None, api_url=None):
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
    """Domain API for PyOTI

    :param domain: Domain to lookup/scan
    """
    def __init__(self, api_key=None, api_url=None, domain=None):
        self._domain = domain
        API.__init__(self, api_key, api_url)

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, value):
        self._domain = value


class FileHash(API):
    """FileHash API for PyOTI

        :param file_hash: File hash to lookup/scan
        """
    def __init__(self, api_key=None, api_url=None, file_hash=None):
        self._file_hash = file_hash
        API.__init__(self, api_key, api_url)

    @property
    def file_hash(self):
        return self._file_hash

    @file_hash.setter
    def file_hash(self, value):
        self._file_hash = value


class IPAddress(API):
    """IPAddress API for PyOTI

        :param ip: IP address to lookup/scan
        """
    def __init__(self, api_key=None, api_url=None, ip=None):
        self._ip = ip
        API.__init__(self, api_key, api_url)

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, value):
        self._ip = value


class URL(API):
    """URL API for PyOTI

        :param url: URL to lookup/scan
        """
    def __init__(self, api_key=None, api_url=None, url=None):
        self._url = url
        API.__init__(self, api_key, api_url)

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        self._url = value


class EmailAddress(API):
    """EmailAddress API for PyOTI

    :param email: Email address to lookup/scan
    """

    def __init__(self, api_key=None, api_url=None, email=None):
        self._email = email
        API.__init__(self, api_key, api_url)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        self._email = value
