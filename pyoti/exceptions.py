class PyOTIError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class GSBPermissionDenied(PyOTIError):
    """Exception raised for Google Safe Browsing API permission errors."""
    pass


class GSBInvalidAPIKey(PyOTIError):
    """Exception raised for Google Safe Browsing API invalid API key error."""
    pass


class SpamhausZenError(PyOTIError):
    """Exception raised for any special codes returned that indicates an error in query."""
    pass

class URLhausHashError(PyOTIError):
    """Exception raised for invalid hash type for URLhaus query."""
    pass